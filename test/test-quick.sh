#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_error() {
    echo -e "${RED}${NC} $1"
}

print_success() {
    echo -e "${GREEN}${NC} $1"
}

check_binary() {
    if [ ! -f "./snake-ebpf" ]; then
        print_error "snake-ebpf binary not found"
        return 1
    fi
    return 0
}

check_bpf_object() {
    if [ ! -f "./bpf/snake.bpf.o" ]; then
        print_error "bpf/snake.bpf.o not found"
        return 1
    fi
    return 0
}

test_bpf_loading() {
    echo "Testing BPF program loading..."
    timeout 2 ./snake-ebpf 2>&1 | head -10 || true
}

run_quick_test() {
    echo "=== Quick Test ==="
    echo ""
    
    local errors=0
    
    if ! check_binary; then
        errors=$((errors + 1))
    else
        print_success "Binary exists"
    fi
    
    if ! check_bpf_object; then
        errors=$((errors + 1))
    else
        print_success "BPF object file exists"
    fi
    
    if [ $errors -gt 0 ]; then
        exit 1
    fi
    
    echo ""
    test_bpf_loading
    
    echo ""
    echo "If you see 'eBPF program attached!' above, the program is working!"
    echo "Run './test.sh' for full interactive test"
}

run_quick_test
