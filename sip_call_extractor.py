#!/usr/bin/env python3

"""
SIP Call Extractor

This script reads a PCAP file, identifies individual SIP calls (including their
associated RTP media streams), and saves each call into a separate PCAP file.
An index CSV file is also generated listing all detected calls and their
corresponding output files.

Design based on sip_extractor_design.md
"""

import argparse
import csv
import hashlib
import logging
import os
import re
import sys
from datetime import datetime

try:
    from scapy.all import PcapReader, PcapWriter, UDP, TCP, Raw
    from scapy.layers.inet import IP
    from scapy.layers.rtp import RTP # Added for RTP analysis
    from scapy.error import Scapy_Exception # Import Scapy_Exception
    # User indicated scapy.layers.sip does not exist, so we will not attempt to import it.
    # SIP processing will rely on port-based detection and raw payload parsing.
    logging.info("Proceeding without Scapy's dedicated SIP layer. Using port-based detection and raw payload parsing for SIP.")
    SIP = None # Ensure SIP is None if it was defined elsewhere or for clarity
except ImportError:
    print("Scapy is not installed. Please install it first: pip install scapy")
    exit(1)

# --- Globals / Configuration ---
APP_NAME = "SIPCallExtractor"
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# active_calls will store call state.
active_calls = {} # Key: Call-ID, Value: call details dict
csv_writer = None # Global for CSV writer instance
csv_file_handle = None # Global for CSV file handle
stats_csv_writer = None # Global for statistics CSV writer instance
stats_csv_file_handle = None # Global for statistics CSV file handle

# --- Logging Setup ---
logger = logging.getLogger(APP_NAME)

def setup_logging(debug=False):
    """Configures basic logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, stream=sys.stderr, force=True)

# --- Helper Functions ---
def generate_call_filename(call_id):
    """Generates a unique filename for a call's PCAP based on its Call-ID."""
    if not call_id:
        call_id = f"unknown_call_{datetime.now().timestamp()}"
    # Use SHA256 hash of the Call-ID, take first 16 chars for brevity
    hashed_call_id = hashlib.sha256(call_id.encode('utf-8')).hexdigest()[:16]
    return f"{hashed_call_id}.pcap"

def sanitize_call_id_for_csv(call_id):
    """Sanitizes Call-ID if it contains characters problematic for CSVs, though usually not an issue."""
    # For now, assume Call-IDs are safe enough or CSV writer handles it.
    # Could replace commas or newlines if they ever appear in Call-IDs.
    return call_id

def parse_sip_ports_range(port_range_str):
    """Parses the SIP port range string (e.g., "5060-5200") into a tuple (start, end)."""
    try:
        start_str, end_str = port_range_str.split('-')
        start_port = int(start_str)
        end_port = int(end_str)
        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError("Invalid port range values.")
        return start_port, end_port
    except ValueError as e:
        logger.error(f"Invalid SIP port range format '{port_range_str}'. Expected START-END. Error: {e}")
        return None

# --- SDP Parsing Logic ---
def parse_sdp(sdp_payload_str, call_data_ref, is_answer=False):
        """
        Parses SDP payload to extract media session information (IP, port, media_type).
        Updates the call_data_ref['media_sessions'] list.
        Prioritizes "answer" SDPs for confirmed sessions.
    
        :param sdp_payload_str: The raw SDP data as a string.
        :param call_data_ref: A reference to the dictionary for the current call in active_calls.
        :param is_answer: Boolean, True if this SDP is from an "answer" (e.g., 200 OK to INVITE).
        """
        logger.debug(f"Parsing SDP for Call-ID: {call_data_ref['call_id']}, is_answer: {is_answer}")
        session_ip = None
        current_media_block_ip = None
        newly_parsed_sessions = []
    
        lines = sdp_payload_str.splitlines()
    
        # First pass for session-level IP
        for line in lines:
            if line.startswith("c=IN IP4 "):
                session_ip = line.split("c=IN IP4 ")[1].strip()
                logger.debug(f"SDP: Found session-level IP: {session_ip}")
                break # Typically one session-level c-line for IP
    
        # Second pass for media descriptions
        media_block_lines = []
        for i, line in enumerate(lines):
            if line.startswith("m="):
                # Process previous media block if any
                if media_block_lines:
                    media_ip_for_block = current_media_block_ip if current_media_block_ip else session_ip
                    if media_ip_for_block and 'port' in media_block_lines[0]: # Ensure m-line was valid
                        media_type = media_block_lines[0]['media']
                        port = media_block_lines[0]['port']
                        # Check for inactive attribute
                        is_inactive = any("a=inactive" in l_str for l_str in media_block_lines[0]['raw_lines'])
                        if not is_inactive:
                            newly_parsed_sessions.append({'ip': media_ip_for_block, 'port': port, 'media': media_type})
                            logger.debug(f"SDP: Parsed media: {media_type} at {media_ip_for_block}:{port}")
                        else:
                            logger.debug(f"SDP: Media {media_type} at {media_ip_for_block}:{port} is inactive, skipping.")
    
                # Start new media block
                media_block_lines = []
                current_media_block_ip = None # Reset for new m-block
                try:
                    parts = line.split(" ", 3) # m=<media> <port> <proto> <fmt>
                    media_type = parts[0].split("=")[1]
                    port = int(parts[1])
                    # Store raw lines for attribute checking like a=inactive
                    media_block_lines.append({'media': media_type, 'port': port, 'raw_lines': [line]})
                except (IndexError, ValueError) as e:
                    logger.warning(f"SDP: Could not parse m-line: {line}. Error: {e}")
                    media_block_lines.append({'raw_lines': [line]}) # Store raw line even if parse fails for attribute check
                    continue
            
            elif media_block_lines: # If we are inside an m-block
                media_block_lines[-1]['raw_lines'].append(line) # Add line to current m-block
                if line.startswith("c=IN IP4 "): # Media-level IP
                    current_media_block_ip = line.split("c=IN IP4 ")[1].strip()
                    logger.debug(f"SDP: Found media-level IP: {current_media_block_ip} for m-line: {media_block_lines[-1]['media']}")
    
    
        # Process the last media block
        if media_block_lines:
            media_ip_for_block = current_media_block_ip if current_media_block_ip else session_ip
            if media_ip_for_block and 'port' in media_block_lines[-1]:
                media_type = media_block_lines[-1]['media']
                port = media_block_lines[-1]['port']
                is_inactive = any("a=inactive" in l_str for l_str in media_block_lines[-1]['raw_lines'])
                if not is_inactive:
                    newly_parsed_sessions.append({'ip': media_ip_for_block, 'port': port, 'media': media_type})
                    logger.debug(f"SDP: Parsed media: {media_type} at {media_ip_for_block}:{port}")
                else:
                    logger.debug(f"SDP: Media {media_type} at {media_ip_for_block}:{port} is inactive, skipping.")
    
        if is_answer:
            # If this is an answer, these are the confirmed sessions.
            # Replace existing media_sessions with these.
            # We also need to consider which IP/port pair to listen on for RTP.
            # SDP usually describes what the *other* side should send to.
            # So, if UA1 sends INVITE with SDP (m=audio 10000, c=UA1_IP), UA1 expects RTP on UA1_IP:10000.
            # If UA2 sends 200 OK with SDP (m=audio 20000, c=UA2_IP), UA2 expects RTP on UA2_IP:20000.
            # The script needs to capture traffic TO these IPs/ports.
            
            # Clear previous sessions if this is a definitive answer
            call_data_ref['media_sessions'].clear()
            for session in newly_parsed_sessions:
                # Store as (IP, Port) tuples that we expect to see traffic FOR.
                call_data_ref['media_sessions'].append((session['ip'], session['port']))
            logger.info(f"SDP (Answer): Updated media sessions for {call_data_ref['call_id']}: {call_data_ref['media_sessions']}")
        else: # Offer
            # For offers, we can also add them, but an answer should override.
            if not call_data_ref['media_sessions']: # If no sessions yet (e.g. from a prior answer)
                for session in newly_parsed_sessions:
                     call_data_ref['media_sessions'].append((session['ip'], session['port']))
                logger.info(f"SDP (Offer): Initial media sessions for {call_data_ref['call_id']}: {call_data_ref['media_sessions']}")

        # Extract ptime from SDP
        # "a=ptime:20"
        for line in lines:
            if line.startswith("a=ptime:"):
                try:
                    ptime_val_str = line.split(":")[1].strip()
                    ptime_val = int(ptime_val_str)
                    call_data_ref['sdp_ptime'] = ptime_val
                    logger.debug(f"SDP: Found ptime: {ptime_val}ms for Call-ID: {call_data_ref['call_id']}")
                    # Typically, one ptime per SDP is dominant. If multiple, last one parsed or logic to prioritize answer's ptime.
                    # For now, any valid ptime updates the call_data_ref.
                    break # Assuming one relevant ptime line or first one is fine
                except (IndexError, ValueError) as e:
                    logger.warning(f"SDP: Could not parse ptime line: {line}. Error: {e}")


# --- RTP Statistics Calculation and Writing ---
def calculate_and_write_rtp_stats(call_data, call_end_time, cli_args_for_debug_info):
    """
    Calculates RTP statistics for all SSRCs in a call and writes them to the stats CSV.
    :param call_data: The dictionary for the call from active_calls.
    :param call_end_time: The timestamp when the call ended or processing stopped for it.
    :param cli_args_for_debug_info: Parsed CLI args, mainly for debug logging context if needed.
    """
    global stats_csv_writer, stats_csv_file_handle
    if not stats_csv_writer:
        logger.warning(f"Statistics CSV writer not initialized. Skipping stats for call {call_data.get('call_id', 'N/A')}.")
        return

    call_start_time_dt = call_data.get('start_time')
    if not call_start_time_dt:
        logger.warning(f"Call start_time missing for call {call_data.get('call_id', 'N/A')}. Cannot calculate duration-based stats.")
        return
    
    call_start_time_ts = call_start_time_dt.timestamp()
    call_duration_seconds = max(0, call_end_time - call_start_time_ts)

    for ssrc, stream_stats in call_data.get('rtp_streams', {}).items():
        if stream_stats['rtp_packet_count'] == 0:
            logger.info(f"SSRC {ssrc} in call {call_data['call_id']} had no RTP packets. Skipping stats row for this SSRC.")
            continue # Skip this SSRC if no packets, proceed to next SSRC

        # Calculate Min/Max/Avg Delta
        if stream_stats['deltas_ms']:
            stream_stats['max_delta_ms'] = max(stream_stats['deltas_ms'])
            stream_stats['min_delta_ms'] = min(stream_stats['deltas_ms'])
            stream_stats['avg_delta_ms'] = sum(stream_stats['deltas_ms']) / len(stream_stats['deltas_ms'])
        else:
            stream_stats['max_delta_ms'] = 0.0
            # If 0 or 1 packet, min_delta_ms is undefined or can be set to 0.0
            stream_stats['min_delta_ms'] = 0.0 if stream_stats['rtp_packet_count'] <= 1 else float('inf')
            stream_stats['avg_delta_ms'] = 0.0

        # Calculate Expected RTP Packets
        ptime_ms = call_data.get('sdp_ptime', 20)
        if ptime_ms > 0 and call_duration_seconds > 0:
            stream_stats['expected_rtp_packets'] = (call_duration_seconds * 1000) / ptime_ms
        else:
            stream_stats['expected_rtp_packets'] = 0

        # Calculate Lost Packets
        num_unique_received = len(stream_stats['received_seq_nums'])
        if num_unique_received > 0 and stream_stats['max_seq_num_seen'] != -1 and stream_stats['expected_min_seq_num'] != -1:
            if stream_stats['max_seq_num_seen'] >= stream_stats['expected_min_seq_num']:
                expected_range_count = (stream_stats['max_seq_num_seen'] - stream_stats['expected_min_seq_num'] + 1)
            else: # Wrapped around
                expected_range_count = (65536 - stream_stats['expected_min_seq_num']) + stream_stats['max_seq_num_seen'] + 1
            stream_stats['lost_packets'] = max(0, expected_range_count - num_unique_received)
        else:
            stream_stats['lost_packets'] = 0
        
        # Out-of-order and duplicate counts are already accumulated during packet processing.

        try:
            stats_csv_writer.writerow([
                call_data.get('call_id', 'N/A'),
                call_start_time_dt.isoformat() if call_start_time_dt else 'N/A',
                call_data.get('output_filename', 'N/A'),
                call_data.get('sip_from', 'N/A'),
                call_data.get('sip_to', 'N/A'),
                f"0x{ssrc:08x}", # SSRC in hex
                stream_stats.get('src_rtp_endpoint', 'N/A'), # Added
                stream_stats.get('dst_rtp_endpoint', 'N/A'), # Added
                stream_stats['rtp_packet_count'],
                round(stream_stats['expected_rtp_packets']),
                stream_stats['lost_packets'],
                stream_stats['out_of_order_count'],
                stream_stats['duplicate_count'],
                f"{stream_stats['max_delta_ms']:.2f}",
                f"{stream_stats['min_delta_ms']:.2f}" if stream_stats['min_delta_ms'] != float('inf') else "0.00",
                f"{stream_stats['avg_delta_ms']:.2f}",
                ptime_ms
            ])
            if stats_csv_file_handle: stats_csv_file_handle.flush()
        except Exception as e_csv:
            # Check if cli_args_for_debug_info is not None and has a 'debug' attribute
            debug_mode = cli_args_for_debug_info.debug if cli_args_for_debug_info and hasattr(cli_args_for_debug_info, 'debug') else False
            logger.error(f"Error writing stats to CSV for call {call_data.get('call_id')} SSRC {ssrc}: {e_csv}", exc_info=debug_mode)

# --- Main Processing Logic ---

def process_packet(packet, current_cli_args, current_sip_ports):
    """
    Processes a single packet to identify SIP and RTP traffic.
    This will be the core logic.

    :param packet: The Scapy packet object.
    :param current_cli_args: The parsed command-line arguments.
    :param current_sip_ports: A tuple (start_port, end_port) for SIP.
    """
    # Placeholder for packet processing logic
    # 1. Check if SIP (based on port and/or Scapy layer)
    # 2. If SIP:
    #    a. Extract Call-ID, method, etc.
    #    b. Handle new call / existing call / call termination
    #    c. Parse SDP if present (offer/answer)
    # 3. Check if RTP (based on media_sessions of active_calls)
    #    a. Write to corresponding call's PcapWriter

    global active_calls, csv_writer # csv_writer is still global for simplicity here

    if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
        return # Not UDP or TCP, unlikely to be SIP/RTP we care about

    # Check for SIP
    is_sip_packet = False
    # sip_layer variable is removed as we are not using Scapy's SIP layer
    src_port, dst_port = None, None

    if packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    if current_sip_ports and src_port is not None: # Ensure ports were found
        if (current_sip_ports[0] <= src_port <= current_sip_ports[1]) or \
           (current_sip_ports[0] <= dst_port <= current_sip_ports[1]):
            is_sip_packet = True
            # No Scapy SIP layer check, port match is sufficient to attempt raw parsing

    if is_sip_packet:
        call_id = None
        sip_method = None
        raw_payload_str = "" # Initialize here to ensure it's always defined within this block

        # We are not using sip_layer, so all parsing must come from Raw payload
        if packet.haslayer(Raw):
            try:
                # Attempt to decode and assign to raw_payload_str
                raw_payload_str = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Extract Call-ID
                call_id_match = re.search(r"Call-ID:\s*([^\r\n]+)", raw_payload_str, re.IGNORECASE)
                if call_id_match:
                    call_id = call_id_match.group(1).strip()
                
                # Extract SIP Method
                if not sip_method: # Try to get method from first line
                    first_line = raw_payload_str.splitlines()[0] if raw_payload_str.splitlines() else ""
                    if "INVITE" in first_line: sip_method = "INVITE"
                    elif "BYE" in first_line: sip_method = "BYE"
                    elif "ACK" in first_line: sip_method = "ACK"
                    elif "CANCEL" in first_line: sip_method = "CANCEL"
                    elif "REGISTER" in first_line: sip_method = "REGISTER"
                    elif "OPTIONS" in first_line: sip_method = "OPTIONS"
                    elif "SIP/2.0" in first_line and " " in first_line: # Response
                        sip_method = f"STATUS_{first_line.split(' ')[1]}"
            except Exception as e:
                logger.debug(f"Could not parse Call-ID/Method from Raw payload: {e}")

        if call_id:
            logger.debug(f"SIP packet detected. Call-ID: {call_id}, Method: {sip_method if sip_method else 'Unknown'}")
            
            if call_id not in active_calls:
                # New call detection: Only start if it's an INVITE
                if sip_method == "INVITE":
                    sip_from_header = "Unknown"
                    sip_to_header = "Unknown"
                    if raw_payload_str: # Ensure raw_payload_str was successfully decoded
                        from_match = re.search(r"^From:\s*(.*)", raw_payload_str, re.IGNORECASE | re.MULTILINE)
                        if from_match:
                            sip_from_header = from_match.group(1).strip()
                        to_match = re.search(r"^To:\s*(.*)", raw_payload_str, re.IGNORECASE | re.MULTILINE)
                        if to_match:
                            sip_to_header = to_match.group(1).strip()

                    output_pcap_filename = generate_call_filename(call_id)
                    full_output_path = os.path.join(current_cli_args.output_dir, output_pcap_filename)
                    
                    try:
                        pcap_writer = PcapWriter(full_output_path, append=False, sync=True)
                        active_calls[call_id] = {
                            'call_id': call_id,
                            'start_time': datetime.fromtimestamp(float(packet.time)), # Convert EDecimal to float
                            'output_pcap_writer': pcap_writer,
                            'output_filename': output_pcap_filename,
                            'media_sessions': [], # List of (ip, port, media_type)
                            'sip_dialog_participants': set(), # Set of (ip, port) tuples
                            'invite_seen': True, # Mark that INVITE has been seen
                            'sip_from': sip_from_header, # Store for CSV
                            'sip_to': sip_to_header,      # Store for CSV
                            'rtp_streams': {}, # For SSRC-specific RTP statistics
                            'sdp_ptime': 20,   # Default ptime, can be updated from SDP
                            'last_activity_time': float(packet.time) # Initialize last activity time
                        }
                        logger.info(f"New call initiated by INVITE: {call_id} (From: {sip_from_header}, To: {sip_to_header}). Output PCAP: {full_output_path}")
                        if csv_writer:
                            csv_writer.writerow([
                                sanitize_call_id_for_csv(call_id),
                                active_calls[call_id]['start_time'].isoformat(),
                                output_pcap_filename,
                                sip_from_header,
                                sip_to_header
                            ])
                            if csv_file_handle: csv_file_handle.flush() # Ensure CSV is written promptly
                    except Exception as e:
                        logger.error(f"Failed to create PcapWriter for call {call_id} at {full_output_path}: {e}")
                        return # Skip further processing for this packet if writer fails
                else:
                    # Not an INVITE and call not active, so ignore for new call creation
                    logger.debug(f"SIP packet for new Call-ID {call_id} is not INVITE (method: {sip_method}). Ignoring for new call capture.")
                    return # Do not process further if not starting with INVITE

            # If call is active (meaning an INVITE was seen and it's in active_calls)
            if call_id in active_calls: # This check is now more specific due to above logic
                call_data = active_calls[call_id]
                try:
                    # Use the correct key 'output_pcap_writer'
                    if 'output_pcap_writer' in call_data and call_data['output_pcap_writer']:
                        call_data['output_pcap_writer'].write(packet)
                        call_data['last_activity_time'] = float(packet.time) # Update last activity time
                    else:
                        logger.error(f"Attempted to write SIP packet for call {call_id}, but 'output_pcap_writer' is missing or None in call_data.")
                except Exception as e:
                    logger.error(f"Failed to write SIP packet to {call_data.get('output_filename', 'unknown_file')}: {e} (Call ID: {call_id})")

                # Add participants (IPs and Ports)
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    call_data['sip_dialog_participants'].add((src_ip, src_port))
                    call_data['sip_dialog_participants'].add((dst_ip, dst_port))
                
                # SDP Parsing
                # Common methods carrying SDP: INVITE, 200 OK (to INVITE), ACK (if SDP was in 200 OK), UPDATE
                is_answer_sdp = False
                if sip_method:
                    if "INVITE" in sip_method and packet.haslayer(Raw): # Offer
                        parse_sdp(packet[Raw].load.decode('utf-8', errors='ignore'), call_data, is_answer=False)
                    elif "STATUS_200" in sip_method and packet.haslayer(Raw): # Could be answer to INVITE
                        # Need to check if this 200 is for an INVITE. CSeq header helps.
                        # For now, assume 200 OK with SDP is an answer.
                        parse_sdp(packet[Raw].load.decode('utf-8', errors='ignore'), call_data, is_answer=True)
                    # ACK can also carry SDP (answer if offer was in 200 OK)
                    # UPDATE can also carry SDP (offer or answer)
                    # More complex logic needed for robust offer/answer state machine.

                # Call Termination (on BYE or CANCEL)
                if sip_method in ["BYE", "CANCEL"]:
                    logger.info(f"{sip_method} detected for call {call_id}. Closing PCAP and calculating stats.")
                    call_end_time = float(packet.time)
                    if call_id in active_calls: # Ensure call_data is valid before operating on it
                        call_data_for_stats = active_calls[call_id] # Get a reference
                        # Calculate and write stats before closing and deleting
                        logger.info(f"{call_id}. call calculate stats")
                        calculate_and_write_rtp_stats(call_data_for_stats, call_end_time, current_cli_args)

                        try:
                            if 'output_pcap_writer' in call_data_for_stats and call_data_for_stats['output_pcap_writer']:
                                call_data_for_stats['output_pcap_writer'].close()
                                logger.debug(f"Closed PCAP writer for call: {call_id} due to {sip_method}")
                            else:
                                logger.warning(f"Attempted to close call {call_id} due to {sip_method}, but 'output_pcap_writer' was missing or None.")
                        except Exception as e:
                            logger.error(f"Error closing PCAP writer for call {call_id} on {sip_method}: {e}")
                        
                        del active_calls[call_id] # Remove from active calls after all operations
                    else:
                        logger.info(f"{call_id} not in active_calls, no status!")
                    # Note: A full SIP dialog would also consider the 200 OK to BYE.
        else:
            logger.debug("SIP-like packet on port, but no Call-ID found or parsed.")
        return # Processed as SIP, or attempted to.

    # Check for RTP if not SIP and if there are active calls with media sessions
    if not is_sip_packet and active_calls:
        if packet.haslayer(IP) and (packet.haslayer(UDP)): # RTP typically over UDP
            packet_ip_src = packet[IP].src
            packet_ip_dst = packet[IP].dst
            packet_port_src = packet[UDP].sport if packet.haslayer(UDP) else packet[TCP].sport # Should be UDP for RTP
            packet_port_dst = packet[UDP].dport if packet.haslayer(UDP) else packet[TCP].dport

            for call_id, call_data in list(active_calls.items()): # Iterate over a copy if modifying
                if not call_data.get('media_sessions'):
                    continue
                
                # media_sessions stores (dest_ip, dest_port) from SDP perspective
                # So we match if packet is going TO one of these.
                for media_ip, media_port in call_data['media_sessions']:
                    if (packet_ip_dst == media_ip and packet_port_dst == media_port) or \
                       (packet_ip_src == media_ip and packet_port_src == media_port): # Also capture return traffic
                        try:
                            # Use the correct key 'output_pcap_writer'
                            if 'output_pcap_writer' in call_data and call_data['output_pcap_writer']:
                                call_data['output_pcap_writer'].write(packet)
                                call_data['last_activity_time'] = float(packet.time) # Update last activity time
                                # logger.debug(f"RTP packet for call {call_id} ({packet_ip_src}:{packet_port_src} -> {packet_ip_dst}:{packet_port_dst}) written to {call_data['output_filename']}")

                                # --- RTP Statistics Processing ---
                                if packet.haslayer(Raw) and UDP in packet: # RTP is usually over UDP and has a payload
                                    try:
                                        rtp_payload_bytes = packet[UDP].payload.load

                                        # Manual RTP Header Parsing for key fields
                                        # Minimum RTP header is 12 bytes
                                        if len(rtp_payload_bytes) < 12:
                                            logger.debug(f"RTP payload too short for call {call_id} ({len(rtp_payload_bytes)} bytes). Skipping.")
                                            # Continue to next iteration or return, depending on loop structure
                                            # In this context, we'd skip this packet for this call_data iteration
                                            # but the outer loop (for media_ip, media_port) might continue.
                                            # For safety, let's assume we skip this packet's processing for stats.
                                            raise ValueError("RTP payload too short")


                                        # Check RTP version (first 2 bits of first byte should be 2)
                                        rtp_version = (rtp_payload_bytes[0] >> 6) & 0x03
                                        if rtp_version != 2:
                                            logger.debug(f"Not an RTP version 2 packet for call {call_id}. Version: {rtp_version}. Skipping.")
                                            raise ValueError("Not RTP version 2")

                                        seq_num = int.from_bytes(rtp_payload_bytes[2:4], 'big')
                                        rtp_ts = int.from_bytes(rtp_payload_bytes[4:8], 'big')
                                        ssrc = int.from_bytes(rtp_payload_bytes[8:12], 'big')
                                        arrival_time = float(packet.time)
                                        
                                        logger.debug(f"RTP Packet: Call-ID: {call_id}, SSRC: {ssrc}, Seq: {seq_num}, TS: {rtp_ts}")

                                        if ssrc not in call_data['rtp_streams']:
                                            # Determine src and dst for this SSRC based on the current RTP packet
                                            # The SSRC identifies the source of this stream.
                                            rtp_src_ep = f"{packet_ip_src}:{packet_port_src}"
                                            rtp_dst_ep = f"{packet_ip_dst}:{packet_port_dst}"

                                            call_data['rtp_streams'][ssrc] = {
                                                'src_rtp_endpoint': rtp_src_ep,
                                                'dst_rtp_endpoint': rtp_dst_ep,
                                                'packets_info': [],
                                                'rtp_packet_count': 0,
                                                'expected_rtp_packets': 0, # To be calculated later
                                                'lost_packets': 0, # To be calculated later
                                                'out_of_order_count': 0,
                                                'duplicate_count': 0,
                                                'deltas_ms': [],
                                                'max_delta_ms': 0.0,
                                                'min_delta_ms': float('inf'),
                                                'avg_delta_ms': 0.0,
                                                'last_arrival_time': None,
                                                'last_seq_num': -1, # Init with invalid seq num
                                                'max_seq_num_seen': -1,
                                                'expected_min_seq_num': -1, # First seq num seen for this SSRC
                                                'received_seq_nums': set()
                                            }
                                        
                                        stream_stats = call_data['rtp_streams'][ssrc]
                                        stream_stats['packets_info'].append((arrival_time, seq_num, rtp_ts))
                                        stream_stats['rtp_packet_count'] += 1

                                        # Calculate Inter-Packet Delta
                                        if stream_stats['last_arrival_time'] is not None:
                                            delta = (arrival_time - stream_stats['last_arrival_time']) * 1000 # ms
                                            stream_stats['deltas_ms'].append(delta)
                                        stream_stats['last_arrival_time'] = arrival_time

                                        # Sequence Number Tracking for Errors
                                        if stream_stats['expected_min_seq_num'] == -1: # First packet for this SSRC
                                            stream_stats['expected_min_seq_num'] = seq_num
                                            stream_stats['last_seq_num'] = seq_num # Initialize last_seq_num
                                            stream_stats['max_seq_num_seen'] = seq_num

                                        if seq_num in stream_stats['received_seq_nums']:
                                            stream_stats['duplicate_count'] += 1
                                        else:
                                            stream_stats['received_seq_nums'].add(seq_num)
                                            # Out-of-order check
                                            # Considered out-of-order if it's less than the max sequence number seen so far for this stream,
                                            # AND it's not a duplicate, AND the difference is not large enough to be a wrap-around.
                                            if seq_num < stream_stats['max_seq_num_seen'] and (stream_stats['max_seq_num_seen'] - seq_num < 0x7FFF): # 0x7FFF is 32767
                                                stream_stats['out_of_order_count'] += 1

                                            # Update last_seq_num for the next packet, only if it's a forward progression (or a valid wrap)
                                            # This helps in identifying out-of-order packets correctly relative to the *last processed in-order* packet.
                                            # However, for simple out-of-order detection against max_seq_num_seen, this specific last_seq_num update logic
                                            # for ooo might be less critical than ensuring max_seq_num_seen is always the highest.
                                            # Let's stick to updating last_seq_num if it's a new, higher sequence number or a wrap.
                                            if seq_num > stream_stats['last_seq_num'] or \
                                               (stream_stats['last_seq_num'] > seq_num and (stream_stats['last_seq_num'] - seq_num) >= 0x7FFF): # Heuristic for wrap
                                                stream_stats['last_seq_num'] = seq_num
                                        
                                        # Update max_seq_num_seen correctly, handling wrap-around
                                        if stream_stats['max_seq_num_seen'] == -1: # First packet
                                            stream_stats['max_seq_num_seen'] = seq_num
                                        elif seq_num > stream_stats['max_seq_num_seen']:
                                            # If seq_num is much smaller, it might be a wrap-around from a high max_seq_num_seen
                                            if (stream_stats['max_seq_num_seen'] > (65535 - 0x7FFF)) and (seq_num < 0x7FFF): # Heuristic: max was high, current is low
                                                stream_stats['max_seq_num_seen'] = seq_num # It wrapped
                                            else: # Normal increment
                                                stream_stats['max_seq_num_seen'] = seq_num
                                        # If seq_num is smaller but not a wrap, max_seq_num_seen doesn't change

                                    except (ValueError, Scapy_Exception) as rtp_e: # Catch specific errors from manual parsing or Scapy
                                        logger.debug(f"Scapy RTP parsing error for call {call_id} on port {packet_port_dst}: {rtp_e}")
                                    except Exception as e_rtp:
                                        logger.error(f"General error processing RTP for call {call_id}: {e_rtp}", exc_info=current_cli_args.debug)
                                # --- End RTP Statistics Processing ---
                            else:
                                logger.error(f"Attempted to write RTP packet for call {call_id}, but 'output_pcap_writer' is missing or None in call_data.")
                        except Exception as e:
                            logger.error(f"Failed to write RTP packet to {call_data.get('output_filename', 'unknown_file')}: {e}") # Use .get for output_filename
                        return # Packet handled for this call

def initialize_csv_writer(output_dir, detected_calls_filename_val):
    """Initializes the CSV writer for the detected calls log."""
    global csv_writer, csv_file_handle # Keep these global for now, or manage them differently
    output_csv_path = os.path.join(output_dir, detected_calls_filename_val)
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        csv_file_handle = open(output_csv_path, 'w', newline='')
        csv_writer = csv.writer(csv_file_handle)
        csv_writer.writerow(['call_id', 'start_timestamp', 'output_pcap_filename', 'sip_from', 'sip_to'])
        logger.info(f"Initialized CSV log at: {output_csv_path}")
    except IOError as e:
        logger.error(f"Failed to initialize CSV writer for {output_csv_path}: {e}")
        # csv_writer will remain None or its previous state if global, ensure it's reset if needed
        if csv_file_handle: # If file was opened but writer failed or other error
            try:
                csv_file_handle.close()
            except IOError:
                pass # Already trying to handle an error
        return False # Indicate failure
    return True # Indicate success

def initialize_stats_csv_writer(output_dir, stats_filename_val):
    """Initializes the CSV writer for the call statistics log."""
    global stats_csv_writer, stats_csv_file_handle
    output_csv_path = os.path.join(output_dir, stats_filename_val)
    try:
        os.makedirs(output_dir, exist_ok=True)
        stats_csv_file_handle = open(output_csv_path, 'w', newline='')
        stats_csv_writer = csv.writer(stats_csv_file_handle)
        headers = [
            'call_id', 'start_timestamp', 'output_pcap_filename', 'sip_from', 'sip_to',
            'ssrc_hex', 'src_rtp_endpoint', 'dst_rtp_endpoint', # Updated/Added
            'rtp_packet_count', 'expected_rtp_packets', 'lost_packets',
            'out_of_order_count', 'duplicate_count', 'max_delta_ms', 'min_delta_ms',
            'avg_delta_ms', 'ptime_ms'
        ]
        stats_csv_writer.writerow(headers)
        logger.info(f"Initialized Statistics CSV log at: {output_csv_path}")
    except IOError as e:
        logger.error(f"Failed to initialize Statistics CSV writer for {output_csv_path}: {e}")
        if stats_csv_file_handle:
            try:
                stats_csv_file_handle.close()
            except IOError:
                pass
        return False
    return True

def close_all_active_calls():
    """Closes all PcapWriters for calls that are still active and calculates final stats."""
    global active_calls
    if not active_calls:
        return
    logger.info(f"Closing {len(active_calls)} active call(s) at the end of PCAP processing and calculating final stats.")
    
    # The calculate_and_write_rtp_stats function can handle cli_args_for_debug_info being None.
    # The debug status for logging within that function will default to False if None is passed.
    # Alternatively, one could pass a simple object or dict like {'debug': logger.isEnabledFor(logging.DEBUG)}
    # if direct cli_args are not available. For now, None is handled.

    for call_id, call_data in list(active_calls.items()): # list() for safe iteration
        call_end_time = call_data.get('last_activity_time', datetime.now().timestamp()) # Fallback if not set
        
        calculate_and_write_rtp_stats(call_data, call_end_time, None)

        if 'output_pcap_writer' in call_data and call_data['output_pcap_writer']:
            try:
                call_data['output_pcap_writer'].close()
                logger.debug(f"Closed PCAP writer for call: {call_id} at final cleanup.")
            except Exception as e:
                logger.error(f"Error closing PCAP writer for call {call_id} at final cleanup: {e}")
        elif call_data.get('output_filename'):
             logger.warning(f"PcapWriter for call {call_id} (file: {call_data['output_filename']}) was expected but not found or already None during final close.")
    active_calls.clear()

def main():
    """Main function to drive the SIP call extraction."""

    parser = argparse.ArgumentParser(description="SIP Call Extractor from PCAP files.")
    parser.add_argument("input_pcap_file", help="Path to the source PCAP file.")
    parser.add_argument("--sip-ports-range", required=True,
                        help="SIP port range (e.g., \"5060-5200\").")
    parser.add_argument("--output-dir", default=".",
                        help="Directory to save extracted PCAP files and CSV log. Default: current directory.")
    parser.add_argument("--detected-calls-filename", default="detected_calls.csv",
                        help="Filename for the CSV index of detected calls. Default: detected_calls.csv.")
    parser.add_argument("--stats-filename", default="calls_statistics.csv",
                        help="Filename for the CSV of call RTP statistics. Default: calls_statistics.csv.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    # Assign to a local variable first, then can be passed around.
    # This also makes it clear that cli_args is specific to this main() scope initially.
    local_cli_args = parser.parse_args()
    print(f"debug: {local_cli_args.debug}")
    setup_logging(local_cli_args.debug)
    logger.info(f"Starting {APP_NAME}...")
    logger.debug(f"CLI Arguments: {local_cli_args}")

    # Assign to a local variable
    local_parsed_sip_ports = parse_sip_ports_range(local_cli_args.sip_ports_range)
    if not local_parsed_sip_ports:
        logger.error("Exiting due to invalid SIP port range.")
        return 1
    
    logger.info(f"Monitoring SIP ports: {local_parsed_sip_ports[0]}-{local_parsed_sip_ports[1]}")

    if not os.path.exists(local_cli_args.input_pcap_file):
        logger.error(f"Input PCAP file not found: {local_cli_args.input_pcap_file}")
        return 1

    if not initialize_csv_writer(local_cli_args.output_dir, local_cli_args.detected_calls_filename):
        logger.error("Exiting due to CSV writer initialization failure.")
        return 1

    if not initialize_stats_csv_writer(local_cli_args.output_dir, local_cli_args.stats_filename):
        logger.error("Exiting due to Statistics CSV writer initialization failure.")
        return 1

    processed_packet_count = 0
    try:
        input_pcap_filepath = local_cli_args.input_pcap_file
        total_file_size = os.path.getsize(input_pcap_filepath)
        logger.info(f"Processing PCAP file: {input_pcap_filepath} (Size: {total_file_size / (1024*1024):.2f} MB)")
        
        with PcapReader(input_pcap_filepath) as pcap_reader:
            for packet in pcap_reader:
                process_packet(packet, local_cli_args, local_parsed_sip_ports) # Pass args
                processed_packet_count += 1
                
                # Progress reporting
                if processed_packet_count % 1000 == 0: # Update progress less frequently than every packet
                    try:
                        current_pos = pcap_reader.f.tell() # Access the underlying file object's tell()
                        progress_percent = (current_pos / total_file_size) * 100
                    except AttributeError: # Fallback if .f is not available or .tell() fails
                        progress_percent = (processed_packet_count / (total_file_size / 1500 if total_file_size > 0 else 1) ) * 100 # Estimate by packets
                        progress_percent = min(progress_percent, 100.0) # Cap at 100%
                        current_pos = int(total_file_size * (progress_percent / 100.0))


                    # Simple text progress bar
                    bar_length = 40
                    filled_length = int(bar_length * current_pos // total_file_size)
                    bar = '█' * filled_length + '-' * (bar_length - filled_length)
                    print(f'\rProgress: |{bar}| {progress_percent:.2f}% ({processed_packet_count} packets)', end='', flush=True)
                    # logger.info logs to a new line, so for continuous progress, direct print is better.
                    # If debug logging is on, this might interleave with log messages.

            # Final progress update after loop
            try:
                current_pos = pcap_reader.f.tell() # Access the underlying file object's tell()
            except AttributeError:
                current_pos = total_file_size # Assume end of file if .f.tell() fails
            
            progress_percent = (current_pos / total_file_size) * 100 if total_file_size > 0 else 100.0
            progress_percent = min(progress_percent, 100.0) # Cap at 100%
            bar_length = 40
            filled_length = int(bar_length * current_pos // total_file_size)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            print(f'\rProgress: |{bar}| {progress_percent:.2f}% ({processed_packet_count} packets)', end='', flush=True)
            print() # Newline after progress bar finishes

        logger.info(f"Finished processing PCAP file. Total packets processed: {processed_packet_count}")

    except Scapy_Exception as e: # Scapy_Exception is a base for Scapy errors
        logger.error(f"Scapy error while processing PCAP: {e}")
    except FileNotFoundError:
        logger.error(f"Input PCAP file disappeared during processing: {local_cli_args.input_pcap_file}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=local_cli_args.debug)
    finally:
        close_all_active_calls()
        if csv_file_handle:
            try:
                csv_file_handle.close()
                logger.info("Closed CSV log file.")
            except IOError as e:
                logger.error(f"Error closing CSV log file: {e}")
        
        if stats_csv_file_handle: # Close statistics CSV
            try:
                stats_csv_file_handle.close()
                logger.info("Closed Statistics CSV log file.")
            except IOError as e:
                logger.error(f"Error closing Statistics CSV log file: {e}")
        logger.info(f"{APP_NAME} finished.")

    return 0

if __name__ == "__main__":
    # Scapy can sometimes have issues with IPv6 routing if not configured.
    # This is a common workaround, though might not be needed for just reading/writing.
    # conf.route6 = None 
    # conf.verb = 0 # Suppress Scapy's own verbose output unless debugging
    
    # For now, let Scapy's default verbosity be, can adjust later.
    # Scapy also prints a warning if not run as root for some functionalities,
    # but for pcap reading/writing it's usually fine.
    
    exit_code = main()
    exit(exit_code)