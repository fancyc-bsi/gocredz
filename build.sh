#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building GoCredz ...${NC}"

# Check for required dependencies
check_dependency() {
    if ! command -v $1 >/dev/null 2>&1; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        return 1
    fi
    return 0
}

# Check for libpcap
check_libpcap() {
    if [ ! -f "/usr/include/pcap.h" ]; then
        echo -e "${RED}Error: libpcap development files not found${NC}"
        echo -e "${YELLOW}Please install libpcap-dev:${NC}"
        echo "Ubuntu/Debian: sudo apt-get install libpcap-dev"
        echo "CentOS/RHEL: sudo yum install libpcap-devel"
        echo "macOS: brew install libpcap"
        return 1
    fi
    return 0
}

# Check dependencies
check_dependency "go" || exit 1
check_dependency "git" || exit 1
check_libpcap || exit 1

# Ensure we're in the project root
if [ ! -f "go.mod" ]; then
    echo -e "${RED}Error: build.sh must be run from the project root${NC}"
    exit 1
fi

# Clean any existing builds
echo "Cleaning previous builds..."
rm -f bin/gocredz

# Set version from git tag if available
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags for optimization
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} "
GOFLAGS="-trimpath"

# Ensure dependencies are downloaded
echo "Downloading dependencies..."
go mod tidy
go mod verify

# Build the optimized binary
echo "Building optimized binary..."
CGO_ENABLED=1 go build \
    ${GOFLAGS} \
    -ldflags="${LDFLAGS}" \
    -o gocredz \
    ./cmd/gnc

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    # Show binary size
    echo "Binary size: $(du -h gocredz | cut -f1)"
    # Show optimization level
    echo "Optimizations applied:"
    echo "- Debug symbols stripped"
    echo "- Paths trimmed"
    
    # Make binary executable
    chmod +x gocredz
    
    echo -e "\nYou can now run: ./gocredz"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Optional UPX compression if available
if command -v upx >/dev/null 2>&1; then
    echo -e "\nCompressing binary with UPX..."
    upx --best --no-progress gocredz
    echo "Final binary size: $(du -h gocredz | cut -f1)"
    mv gocredz bin/gocredz
    echo -e "\n final binary moved to bin/gocredz"
else
    echo -e "\nNote: Install UPX for additional binary compression"
fi
