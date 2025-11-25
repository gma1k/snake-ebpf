#!/bin/bash

set -e

ERRORS=0
WARNINGS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((ERRORS++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARNINGS++))
}

check_go() {
    echo "1. Checking Go installation..."
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}')
        check_pass "Go is installed: $GO_VERSION"
        
        # Check Go version (should be 1.24+)
        GO_MAJOR=$(echo $GO_VERSION | sed 's/go//' | cut -d. -f1)
        GO_MINOR=$(echo $GO_VERSION | sed 's/go//' | cut -d. -f2)
        if [ "$GO_MAJOR" -gt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 24 ]); then
            check_pass "Go version is 1.24 or later"
        else
            check_warn "Go version should be 1.24 or later (found: $GO_VERSION)"
        fi
    else
        check_fail "Go is not installed or not in PATH"
        echo "   Add to PATH: export PATH=\$PATH:\$HOME/.local/go/bin"
    fi
    echo ""
}

check_go_modules() {
    echo "2. Checking Go module dependencies..."
    if [ -f "go.mod" ]; then
        check_pass "go.mod file exists"
        
        if [ -f "go.sum" ]; then
            check_pass "go.sum file exists"
        else
            check_warn "go.sum file missing - run: go mod download"
        fi
        
        # Check if dependencies are downloaded
        if [ -d "$(go env GOPATH)/pkg/mod" ] || [ -d "$HOME/go/pkg/mod" ]; then
            check_pass "Go module cache exists"
        else
            check_warn "Go modules may not be downloaded - run: go mod download"
        fi
    else
        check_fail "go.mod file not found"
    fi
    echo ""
}

check_build_tools() {
    echo "3. Checking build tools..."
    if command -v clang &> /dev/null; then
        CLANG_VERSION=$(clang --version | head -n1)
        check_pass "clang is installed: $CLANG_VERSION"
    else
        check_fail "clang is not installed"
        echo "   Install: sudo apt-get install clang"
    fi

    if command -v llvm-strip &> /dev/null; then
        check_pass "llvm-strip is installed"
    else
        check_fail "llvm-strip is not installed"
        echo "   Install: sudo apt-get install llvm"
    fi

    if command -v bpftool &> /dev/null; then
        check_pass "bpftool is installed"
    else
        check_warn "bpftool is not installed (optional, but recommended)"
        echo "   Install: sudo apt-get install bpftool"
    fi
    echo ""
}

check_kernel_headers() {
    echo "4. Checking kernel headers..."
    KERNEL_VERSION=$(uname -r)
    KERNEL_HEADERS="/usr/src/linux-headers-$KERNEL_VERSION"

    if [ -d "$KERNEL_HEADERS" ]; then
        check_pass "Kernel headers found: $KERNEL_HEADERS"
    else
        check_fail "Kernel headers not found: $KERNEL_HEADERS"
        echo "   Install: sudo apt-get install linux-headers-$KERNEL_VERSION"
    fi
    echo ""
}

check_libbpf() {
    echo "5. Checking libbpf headers..."
    if [ -f "/usr/include/bpf/bpf.h" ] || [ -f "/usr/include/bpf/bpf_helpers.h" ]; then
        check_pass "libbpf headers found"
    else
        check_warn "libbpf headers not found in /usr/include/bpf/"
        echo "   Install: sudo apt-get install libbpf-dev"
    fi
    echo ""
}

check_ebpf_support() {
    echo "6. Checking eBPF support..."
    if [ -d "/sys/fs/bpf" ]; then
        check_pass "eBPF filesystem mounted: /sys/fs/bpf"
    else
        check_warn "eBPF filesystem not mounted (may need: sudo mount -t bpf none /sys/fs/bpf)"
    fi

    if [ -d "/sys/kernel/debug/tracing" ]; then
        check_pass "Kernel tracing available: /sys/kernel/debug/tracing"
    else
        check_warn "Kernel tracing not available (may need to mount debugfs)"
    fi
    echo ""
}

check_project_files() {
    echo "7. Checking project files..."
    if [ -f "bpf/snake.bpf.c" ]; then
        check_pass "eBPF source file exists: bpf/snake.bpf.c"
    else
        check_fail "eBPF source file missing: bpf/snake.bpf.c"
    fi

    if [ -f "bpf/Makefile" ]; then
        check_pass "eBPF Makefile exists: bpf/Makefile"
    else
        check_fail "eBPF Makefile missing: bpf/Makefile"
    fi

    if [ -f "main.go" ]; then
        check_pass "Go source file exists: main.go"
    else
        check_fail "Go source file missing: main.go"
    fi
    echo ""
}

check_artifacts() {
    echo "8. Checking compiled artifacts..."
    if [ -f "bpf/snake.bpf.o" ]; then
        check_pass "eBPF object file exists: bpf/snake.bpf.o"
        FILE_TYPE=$(file bpf/snake.bpf.o 2>/dev/null | grep -o "ELF" || echo "")
        if [ "$FILE_TYPE" = "ELF" ]; then
            check_pass "eBPF object file is valid ELF"
        else
            check_warn "eBPF object file may be invalid"
        fi
    else
        check_warn "eBPF object file not found: bpf/snake.bpf.o"
        echo "   Build it: cd bpf && make"
    fi

    if [ -f "snake-ebpf" ]; then
        check_pass "Go binary exists: snake-ebpf"
        if [ -x "snake-ebpf" ]; then
            check_pass "Go binary is executable"
        else
            check_warn "Go binary is not executable - run: chmod +x snake-ebpf"
        fi
    else
        check_warn "Go binary not found: snake-ebpf"
        echo "   Build it: go build -o snake-ebpf main.go"
    fi
    echo ""
}

check_permissions() {
    echo "9. Checking permissions..."
    if [ "$EUID" -eq 0 ]; then
        check_pass "Running as root (can attach eBPF programs)"
    elif getcap ./snake-ebpf 2>/dev/null | grep -q "cap_bpf"; then
        check_pass "Binary has eBPF capabilities set"
        getcap ./snake-ebpf
    else
        check_warn "Not running as root and no capabilities set"
        echo "   Options:"
        echo "   1. Run with sudo: sudo ./snake-ebpf"
    fi
    echo ""
}

test_compilation() {
    echo "10. Testing compilation..."
    echo "   Testing eBPF compilation..."
    cd bpf 2>/dev/null
    if make clean >/dev/null 2>&1 && make >/dev/null 2>&1; then
        check_pass "eBPF program compiles successfully"
        cd ..
    else
        check_fail "eBPF program compilation failed"
        echo "   Run 'cd bpf && make' to see errors"
        cd ..
    fi

    echo ""
    echo "   Testing Go compilation..."
    if go build -o snake-ebpf-test main.go >/dev/null 2>&1; then
        check_pass "Go program compiles successfully"
        rm -f snake-ebpf-test
    else
        check_fail "Go program compilation failed"
        echo "   Run 'go build -o snake-ebpf main.go' to see errors"
    fi
    echo ""
}

print_summary() {
    echo "=========================================="
    echo "  Summary"
    echo "=========================================="

    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✓ All checks passed! Setup is complete.${NC}"
        echo ""
        echo "You can now run:"
        echo "  sudo ./snake-ebpf"
        exit 0
    elif [ $ERRORS -eq 0 ]; then
        echo -e "${YELLOW}⚠ Setup is mostly complete with $WARNINGS warning(s)${NC}"
        echo ""
        echo "You can try running:"
        echo "  sudo ./snake-ebpf"
        exit 0
    else
        echo -e "${RED}✗ Setup has $ERRORS error(s) and $WARNINGS warning(s)${NC}"
        echo ""
        echo "Please fix the errors above before running the application."
        exit 1
    fi
}

main() {
    echo "=========================================="
    echo "  Snake eBPF Setup Verification"
    echo "=========================================="
    echo ""

    check_go
    check_go_modules
    check_build_tools
    check_kernel_headers
    check_libbpf
    check_ebpf_support
    check_project_files
    check_artifacts
    check_permissions
    test_compilation
    print_summary
}

main
