# Testing Guide for Snake eBPF

## Quick Test

Run the quick test to verify everything is set up:

```bash
./test-quick.sh
```

## Full Test

Run the full test script:

```bash
./test.sh
```

## Manual Testing Steps

### 1. Verify Build

```bash
# Build eBPF program
cd bpf && make && cd ..

# Build Go application
go build -o snake-ebpf main.go

# Check files exist
ls -lh snake-ebpf bpf/snake.bpf.o
```

### 2. Test with Sudo

```bash
sudo ./snake-ebpf
```

### Test 3: Verify Go Dependencies

```bash
go mod verify
go mod download
```

## Automated Testing

You can also create a simple automated test:

```bash
# Run for 5 seconds and check for errors
timeout 5 sudo ./snake-ebpf 2>&1 | grep -i error
```
