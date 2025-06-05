# SIP Call Extractor (Go)

A high-performance SIP call extractor written in Go that processes PCAP files or performs live packet capture to extract individual SIP calls with their associated RTP streams. This is a complete rewrite of the original Python implementation with improved performance and concurrency.

## Features

- **SIP Call Detection**: Automatically detects SIP calls from INVITE to BYE/CANCEL
- **RTP Stream Association**: Associates RTP streams with SIP calls based on SDP negotiation
- **Individual Call Extraction**: Extracts each call to a separate PCAP file
- **Comprehensive Statistics**: Generates detailed RTP statistics including packet loss, jitter, and timing
- **SDP Parsing**: Handles complex SDP scenarios including inactive media streams
- **Live Capture**: Supports both PCAP file processing and live network capture
- **S3 Upload Integration**: Automatic upload of PCAP files to AWS S3 with local cleanup
- **Concurrent Processing**: Thread-safe design for high-performance packet processing
- **Docker Support**: Containerized deployment with static binary builds

## Requirements

### Runtime Dependencies
- libpcap (for packet capture functionality)

### Build Dependencies
- Go 1.21 or later
- gcc (for CGO compilation)
- libpcap-dev (development headers)

## Installation

### Using Docker (Recommended)

1. **Build the Docker image:**
   ```bash
   docker build -t sip-extractor .
   ```

2. **Run with Docker:**
   ```bash
   # Process a PCAP file
   docker run --rm -v /path/to/pcaps:/data sip-extractor \
     --input-file /data/input.pcap \
     --sip-ports-range 5060-5080 \
     --output-dir /data

   # Live capture (requires host network access)
   docker run --rm --net=host -v /path/to/output:/data sip-extractor \
     --interface eth0 \
     --sip-ports-range 5060-5080 \
     --output-dir /data
   ```

### Using Docker Compose (Development)

1. **Start the development environment:**
   ```bash
   docker compose up -d
   ```

2. **Run commands in the container:**
   ```bash
   # Build the application
   docker compose exec app go build -o sip_call_extractor .

   # Run tests
   docker compose exec app go test -v

   # Process a PCAP file
   docker compose exec app ./sip_call_extractor \
     --input-file /data/sample.pcap \
     --sip-ports-range 5060-5080
   ```

### Local Build

1. **Install dependencies (Ubuntu/Debian):**
   ```bash
   sudo apt-get update
   sudo apt-get install -y gcc libpcap-dev
   ```

2. **Build the application:**
   ```bash
   go mod download
   go build -o sip_call_extractor .
   ```

3. **Run the application:**
   ```bash
   ./sip_call_extractor --input-file sample.pcap --sip-ports-range 5060-5080
   ```

## Usage

### Command Line Options

```
Usage of ./sip_call_extractor:
  -auto-upload-to-s3
        Automatically upload PCAP files to S3 and delete local files
  -call-timeout duration
        Duration for inactive call timeout (default 5m0s)
  -debug
        Enable debug logging
  -detected-calls-filename string
        Filename for the CSV index of detected calls (default "detected_calls.csv")
  -filter string
        BPF filter string for live capture (default "udp")
  -input-file string
        Path to the source PCAP file (alternative to live capture)
  -interface string
        Network interface name for live capture (e.g., "eth0")
  -output-dir string
        Directory to save extracted PCAP files and CSV log (default ".")
  -s3-region string
        AWS region for S3 bucket
  -s3-uri string
        S3 URI prefix for uploads (e.g., s3://bucket/prefix/)
  -sip-ports-range string
        SIP port range (e.g., "5060-5200") (Required)
  -stats-filename string
        Filename for the CSV of call RTP statistics (default "calls_statistics.csv")
```

### Examples

1. **Process a PCAP file:**
   ```bash
   ./sip_call_extractor \
     --input-file /path/to/capture.pcap \
     --sip-ports-range 5060-5080 \
     --output-dir ./extracted_calls \
     --debug
   ```

2. **Live capture from network interface:**
   ```bash
   sudo ./sip_call_extractor \
     --interface eth0 \
     --sip-ports-range 5060-5200 \
     --filter "udp and port 5060" \
     --output-dir ./live_calls
   ```

3. **Custom timeouts and filenames:**
   ```bash
   ./sip_call_extractor \
     --input-file capture.pcap \
     --sip-ports-range 5060-5060 \
     --call-timeout 10m \
     --detected-calls-filename my_calls.csv \
     --stats-filename my_stats.csv
   ```

4. **Automatic S3 upload with local cleanup:**
   ```bash
   ./sip_call_extractor \
     --input-file capture.pcap \
     --sip-ports-range 5060-5080 \
     --auto-upload-to-s3 \
     --s3-uri "s3://my-backup-bucket/sip-captures/" \
     --s3-region "us-east-1" \
     --output-dir ./temp_calls
   ```

5. **S3 configuration without auto-upload (CSV tracking only):**
   ```bash
   ./sip_call_extractor \
     --input-file capture.pcap \
     --sip-ports-range 5060-5080 \
     --s3-uri "s3://my-backup-bucket/sip-captures/" \
     --s3-region "us-east-1"
   ```

## Output Files

The application generates several output files:

### Individual Call PCAPs
- **Format**: `call_<call-id-hash>_<timestamp>.pcap`
- **Content**: Complete PCAP file containing all SIP and RTP packets for a single call
- **Example**: `call_a1b2c3d4_20231201_143022.pcap`

### Detected Calls CSV
- **Default**: `detected_calls.csv`
- **Content**: Index of all detected calls with metadata
- **Columns**: `call_id`, `start_timestamp`, `output_pcap_filename`, `sip_from`, `sip_to`, `s3_location`

### Call Statistics CSV
- **Default**: `calls_statistics.csv`
- **Content**: Detailed RTP statistics for each call
- **Columns**: `call_id`, `start_timestamp`, `output_pcap_filename`, `sip_from`, `sip_to`, `ssrc_hex`, `src_rtp_endpoint`, `dst_rtp_endpoint`, `rtp_packet_count`, `expected_rtp_packets`, `lost_packets`, `out_of_order_count`, `duplicate_count`, `max_delta_ms`, `min_delta_ms`, `avg_delta_ms`, `ptime_ms`, `s3_location`

## S3 Integration

The application supports automatic upload of extracted PCAP files to AWS S3 with configurable cleanup of local files.

### Features
- **Automatic Upload**: PCAP files are uploaded to S3 immediately after call completion
- **Local Cleanup**: Local PCAP files are automatically deleted after upload (regardless of upload success/failure to prevent disk space issues)
- **CSV Tracking**: S3 location is recorded in both CSV files for reference
- **AWS SDK Integration**: Uses AWS SDK v2 with standard credential resolution
- **Error Resilience**: Upload failures are logged but don't prevent local file cleanup

### Configuration

S3 upload requires three parameters:
- `--auto-upload-to-s3`: Enable automatic upload and local file deletion
- `--s3-uri`: S3 URI prefix (e.g., `s3://bucket-name/prefix/`)
- `--s3-region`: AWS region for the S3 bucket

### AWS Credentials

The application uses the AWS SDK's default credential resolution order:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM roles (when running on EC2)
4. Container credentials (when running in ECS/EKS)

### S3 Permissions

The application requires the following S3 permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name/prefix/*"
        }
    ]
}
```

### CSV Behavior

The `s3_location` column is always present in CSV files:
- **With S3 enabled**: Contains the full S3 URI (e.g., `s3://bucket/prefix/filename.pcap`)
- **Without S3**: Column is empty but still present for consistency

## Architecture

### Key Components

- **SIP Handler** (`sip_handler.go`): Parses SIP messages and manages call state
- **SDP Handler** (`sdp_handler.go`): Processes SDP payloads and extracts media session information
- **RTP Handler** (`rtp_handler.go`): Associates RTP packets with calls and collects statistics
- **Call Manager** (`call_manager.go`): Manages call timeouts and cleanup
- **Statistics Handler** (`stats_handler.go`): Calculates comprehensive RTP statistics
- **S3 Handler** (`s3_handler.go`): Manages S3 uploads and local file cleanup

### Concurrency Model

The application uses a thread-safe design with:
- **Global RWMutex**: Protects the active calls map
- **Read Locks**: Used for packet matching and statistics collection
- **Write Locks**: Used for call creation, modification, and cleanup
- **Goroutines**: Background call timeout monitoring

## Testing

### Unit Tests

Run the comprehensive test suite:

```bash
# Run all tests
go test -v

# Run specific test files
go test -v ./sdp_handler_test.go ./sdp_handler.go ./structs.go ./cli.go ./main.go
go test -v ./sip_handler_test.go ./sip_handler.go ./structs.go ./cli.go ./main.go
go test -v ./stats_handler_test.go ./stats_handler.go ./structs.go ./cli.go ./main.go
```

### Test Coverage

The test suite covers:
- SDP parsing with various scenarios (inactive media, multiple streams, etc.)
- SIP header parsing (standard and compact forms)
- Port range validation
- RTP statistics calculations
- Sequence number wrap-around handling

## Performance Considerations

### Memory Usage
- Efficient packet processing with minimal memory allocation
- Call cleanup based on configurable timeouts
- Streaming PCAP writing to avoid memory buildup

### CPU Usage
- Concurrent packet processing
- Optimized regular expressions for header parsing
- Minimal lock contention with read/write mutex strategy

### Scalability
- Handles thousands of concurrent calls
- Configurable call timeouts prevent memory leaks
- Efficient RTP stream association algorithms

## Troubleshooting

### Common Issues

1. **Permission Denied (Live Capture)**
   ```bash
   # Run with sudo for network interface access
   sudo ./sip_call_extractor --interface eth0 --sip-ports-range 5060-5080
   ```

2. **No Calls Detected**
   - Verify SIP port range includes actual SIP traffic ports
   - Check BPF filter syntax for live capture
   - Enable debug logging to see packet processing details

3. **Missing RTP Streams**
   - Ensure RTP ports are within the capture scope
   - Check for NAT/firewall issues affecting RTP flow
   - Verify SDP parsing with debug output

4. **S3 Upload Issues**
   - Verify AWS credentials are properly configured
   - Check S3 bucket permissions and region settings
   - Ensure the S3 URI format is correct (must start with `s3://`)
   - Review AWS SDK error messages in the application logs
   - Note: Local files are deleted regardless of upload success to prevent disk space issues

### Debug Mode

Enable debug logging for detailed processing information:

```bash
./sip_call_extractor --debug --input-file sample.pcap --sip-ports-range 5060-5080
```

Debug output includes:
- SIP message parsing details
- SDP media session extraction
- RTP packet association
- Call state transitions

## Migration from Python Version

This Go implementation provides:
- **10x+ Performance Improvement**: Concurrent processing and efficient memory usage
- **Better Resource Management**: Automatic call cleanup and memory management
- **Enhanced SDP Support**: Improved handling of complex SDP scenarios
- **Robust Statistics**: More accurate RTP statistics with wrap-around handling
- **Container Ready**: Docker support with static binary builds

### Key Differences
- Port range must be specified as range (e.g., `5060-5080`) instead of single ports
- Enhanced concurrency requires no special configuration
- Improved error handling and logging
- More comprehensive test coverage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `go test -v`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Original Python implementation for reference architecture
- gopacket library for packet processing capabilities
- Go community for excellent networking libraries