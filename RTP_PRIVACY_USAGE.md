# RTP Privacy Features Usage Guide

This document explains how to use the new RTP payload clearing features in the SIP Call Extractor for privacy protection.

## Overview

The SIP Call Extractor now supports selectively clearing RTP payloads from captured PCAP files while preserving packet headers and metadata. This allows you to maintain call statistics and flow analysis while protecting the actual audio content.

## Command Line Options

### Global RTP Payload Clearing

```bash
--no-rtp-dump
```
Clears RTP payload for all calls.

**Example:**
```bash
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump
```

### Pattern-Based Clearing

#### Clear payload when patterns match:

```bash
--no-rtp-dump-for-callid-pattern '<regexp>'
--no-rtp-dump-for-from-pattern '<regexp>'
--no-rtp-dump-for-to-pattern '<regexp>'
```

**Examples:**
```bash
# Clear payload for calls with Call-ID containing "sensitive"
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump-for-callid-pattern ".*sensitive.*"

# Clear payload for calls from specific users
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump-for-from-pattern ".*confidential@.*"

# Clear payload for calls to specific destinations
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump-for-to-pattern ".*@private\.domain\.com"
```

#### Preserve payload when patterns match (clear otherwise):

```bash
--no-rtp-dump-except-for-callid-pattern '<regexp>'
--no-rtp-dump-except-for-from-pattern '<regexp>'
--no-rtp-dump-except-for-to-pattern '<regexp>'
```

**Examples:**
```bash
# Clear all payloads EXCEPT for calls with Call-ID containing "public"
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump-except-for-callid-pattern ".*public.*"

# Clear all payloads EXCEPT for calls from test users
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap --no-rtp-dump-except-for-from-pattern ".*test@.*"
```

## Decision Logic Priority

The rules are applied in the following priority order:

1. **Preservation Rule (Highest Priority):** If any `--no-rtp-dump-except-for-*-pattern` matches, the payload is **NOT cleared**.

2. **Global Dump Rule:** If `--no-rtp-dump` is true, the payload **IS cleared**.

3. **Targeted Dump Rule:** If any `--no-rtp-dump-for-*-pattern` matches, the payload **IS cleared**.

4. **Implicit Dump Rule:** If any `--no-rtp-dump-except-for-*-pattern` was provided but did NOT match, the payload **IS cleared**.

5. **Default:** If none of the above conditions are met, the payload is **NOT cleared**.

## Regular Expression Patterns

All pattern flags accept standard Go regular expressions. Some useful patterns:

- `.*` - Matches anything
- `^test.*` - Starts with "test"
- `.*@example\.com$` - Ends with "@example.com"
- `(alice|bob)@.*` - Matches "alice@" or "bob@" followed by anything
- `.*confidential.*` - Contains "confidential" anywhere

## Combining Multiple Rules

You can combine multiple rules. The preservation rules (`except-for`) always take precedence:

```bash
# Clear all payloads globally, but preserve calls from admin users
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap \
  --no-rtp-dump \
  --no-rtp-dump-except-for-from-pattern ".*admin@.*"

# Clear payloads for sensitive calls, but preserve test calls
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap \
  --no-rtp-dump-for-callid-pattern ".*sensitive.*" \
  --no-rtp-dump-except-for-from-pattern ".*test@.*"
```

## What Gets Cleared

When RTP payload clearing is activated:

- **Preserved:** RTP headers, UDP headers, IP headers, packet timing, sequence numbers
- **Cleared:** Only the actual media payload (audio/video data)
- **Result:** PCAP files can still be analyzed for call flow, statistics, and network behavior, but audio cannot be reconstructed

## Technical Details

- The tool correctly parses RTP headers including CSRC lists, extensions, and padding
- Only the media payload portion is zeroed out
- Packet structure and lengths remain unchanged
- All existing statistics and analysis features continue to work normally

## Error Handling

If you provide an invalid regular expression, the tool will exit with a clear error message:

```bash
Error: Invalid regex for --no-rtp-dump-for-callid-pattern: error parsing regexp: missing closing ]: `[invalid`
```

## Debug Information

Use the `--debug` flag to see detailed information about payload clearing decisions:

```bash
./sip_call_extractor --sip-ports-range "5060-5070" --input-file capture.pcap \
  --no-rtp-dump-for-callid-pattern ".*test.*" --debug
```

This will show messages like:
```
DEBUG: CallID: test-call-123 - Cleared RTP payload (256 bytes) due to privacy rules