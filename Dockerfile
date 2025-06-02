# ---- Build Stage ----
FROM golang:1.21-alpine AS builder
WORKDIR /app

# Install build dependencies for pcap (libpcap-dev)
# and other tools that might be useful in the build stage (e.g., git)
RUN apk add --no-cache gcc musl-dev libpcap-dev git

# COPY . . will handle go.mod and go.sum if they exist.
# For the initial 'go mod init', they won't exist yet.
COPY . .

# Build static executable
RUN CGO_ENABLED=1 GOOS=linux go build -v -a -tags netgo -ldflags '-w -s -extldflags "-static"' -o sip_call_extractor .

# ---- Runtime Stage ----
# This stage is for the final, small image once the binary is built.
# We will primarily use the 'builder' stage for development commands for now.
FROM alpine:latest
WORKDIR /app

# libpcap is needed at runtime if dynamically linked.
# For CGO_ENABLED=1 and gopacket/pcap, libpcap is usually needed.
RUN apk add --no-cache libpcap

COPY --from=builder /app/sip_call_extractor .
# COPY any other necessary assets (e.g. default config if any)

ENTRYPOINT ["./sip_call_extractor"]
# CMD ["--help"] # Optional: default command if no args to entrypoint