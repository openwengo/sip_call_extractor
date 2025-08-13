# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build Commands
```bash
# Local development build
go build -o sip_call_extractor .

# Static build (for production/containers)
CGO_ENABLED=1 GOOS=linux go build -v -a -tags netgo -ldflags '-w -s -extldflags "-static"' -o sip_call_extractor .
```

### Docker Development
```bash
# Build Docker image
docker build -t sip-extractor .

# Development with Docker Compose
docker compose up -d              # Start development container
docker compose exec app go build -buildvcs=false -o sip_call_extractor .
docker compose exec app go test -v
```

### Testing
```bash
# Run all tests
go test -v

# Run specific test files
go test -v ./sdp_handler_test.go ./sdp_handler.go ./structs.go ./cli.go ./main.go
go test -v ./sip_handler_test.go ./sip_handler.go ./structs.go ./cli.go ./main.go
go test -v ./stats_handler_test.go ./stats_handler.go ./structs.go ./cli.go ./main.go
go test -v ./erspan_handler_test.go ./erspan_handler.go ./structs.go ./cli.go ./main.go
go test -v ./fragment_handler_test.go ./fragment_handler.go ./structs.go ./cli.go ./main.go
```

### Dependencies
```bash
# Install/update dependencies
go mod download
go mod tidy
```

## Architecture Overview

### Core Components
- **main.go**: Application entry point with packet capture loop and global state management
- **cli.go**: Command-line argument parsing and configuration handling
- **config.go**: Configuration file parsing (supports .conf files with sections)
- **structs.go**: Core data structures (Call, MediaSession, RTPStreamStats, etc.)

### Processing Pipeline
1. **Packet Capture**: Live capture or PCAP file reading
2. **Fragment Assembly**: IP fragmentation reassembly (`fragment_handler.go`)
3. **ERSPAN Processing**: Cisco ERSPAN Type I/II/III decapsulation (`erspan_handler.go`)
4. **Protocol Handlers**:
   - **SIP Handler** (`sip_handler.go`): SIP message parsing and call state management
   - **SDP Handler** (`sdp_handler.go`): Media session extraction from SDP
   - **RTP Handler** (`rtp_handler.go`): RTP packet association and statistics
5. **Output Generation**: Individual call PCAPs and CSV statistics

### Concurrency Model
- **Global RWMutex** (`activeCallsMutex`): Protects the main `activeCalls` map
- **Media Session Map** (`activeMediaSessions`): Efficient RTP-to-call mapping with separate mutex
- **Call Timeout Management** (`call_manager.go`): Background goroutine for call cleanup
- Thread-safe design allows concurrent packet processing

### Key Data Structures
- **Call**: Represents an active SIP call with associated RTP streams and PCAP writer
- **MediaSession**: IP/port pair for RTP stream identification
- **RTPStreamStats**: Per-SSRC statistics including packet loss, jitter, timing
- **MediaSessionKey**: Efficient map key for RTP packet lookup

## Development Guidelines

### Adding New Handlers
- Follow the existing pattern: separate file for each protocol
- Use global mutexes for thread safety
- Include comprehensive test coverage
- Handle edge cases (malformed packets, missing headers)

### Configuration System
- Configuration files support INI-style sections
- Command-line parameters override config file values
- See `sipcapture.conf.example` for all available options

### Testing Strategy
- Unit tests for each handler component
- Test files include edge cases and malformed data
- Use `go test -v` to see detailed test output
- Mock data structures are defined in test files

### Performance Considerations
- Global media session map reduces RTP packet lookup overhead
- Streaming PCAP writing prevents memory buildup
- Configurable call timeouts prevent memory leaks
- Fragment reassembly has configurable limits and timeouts

## Common Development Tasks

### Adding New SIP Header Support
1. Update SIP parsing regex in `sip_handler.go`
2. Add field to Call struct in `structs.go`
3. Update CSV output in CSV handler if needed
4. Add test cases in `sip_handler_test.go`

### Extending RTP Statistics
1. Add fields to `RTPStreamStats` in `structs.go`
2. Update calculation logic in `stats_handler.go`
3. Modify CSV output format
4. Add test coverage in `stats_handler_test.go`

### Adding New Protocol Support
1. Create new handler file (e.g., `protocol_handler.go`)
2. Add packet processing logic to main packet loop
3. Update global state structures if needed
4. Include comprehensive test coverage

## Build Requirements
- Go 1.21+
- CGO enabled (for libpcap integration)
- libpcap-dev (development headers)
- gcc (for CGO compilation)

## Special Features
- **ERSPAN Support**: Processes Cisco ERSPAN Type I/II/III encapsulated traffic
- **IP Fragmentation**: Automatic reassembly of fragmented packets
- **S3 Integration**: Automatic upload with hostname macro support
- **RTP Privacy**: Configurable RTP payload clearing based on regex patterns
- **Live Capture**: Real-time packet processing with capture statistics