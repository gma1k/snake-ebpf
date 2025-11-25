#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_error() {
    echo -e "${RED} Error:${NC} $1"
}

print_success() {
    echo -e "${GREEN}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW} Warning:${NC} $1"
}

check_binary() {
    if [ ! -f "./snake-ebpf" ]; then
        print_error "snake-ebpf binary not found"
        echo "   Build it first: go build -o snake-ebpf main.go"
        return 1
    fi
    return 0
}

check_bpf_object() {
    if [ ! -f "./bpf/snake.bpf.o" ]; then
        print_error "bpf/snake.bpf.o not found"
        echo "   Build it first: cd bpf && make"
        return 1
    fi
    return 0
}

check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        print_success "Running as root - good for eBPF"
        return 0
    elif getcap ./snake-ebpf 2>/dev/null | grep -q "cap_bpf"; then
        print_success "Binary has required capabilities"
        return 0
    else
        print_warning "Not running as root and no capabilities set"
        echo "   Run with: sudo ./snake-ebpf"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    return 0
}

print_instructions() {
    echo ""
    echo "=== Test Instructions ==="
    echo "1. The game will start automatically"
    echo "2. Use WASD keys to move the snake"
    echo "3. The snake will grow as system events are detected"
    echo "4. Press Q or Ctrl+C to quit"
    echo ""
    echo "To trigger system events (to influence game speed), open another terminal and run:"
    echo "   ls"
    echo "   cat /etc/passwd"
    echo "   echo 'test'"
    echo "   (any command will trigger execve and file operations)"
    echo ""
}

run_test() {
    echo "=== Snake eBPF Test Script ==="
    echo ""
    
    if ! check_binary; then
        exit 1
    fi
    
    if ! check_bpf_object; then
        exit 1
    fi
    
    if ! check_permissions; then
        exit 1
    fi
    
    print_instructions
    
    echo "Starting game in 3 seconds..."
    sleep 3
    
    ./snake-ebpf
}

run_test
