<p align="center">
  <a href="https://github.com/gma1k/snake-ebpf">
    <img src="https://github.com/gma1k/snake-ebpf/blob/main/assets/snake-ebpf.png" width="420" alt="snake-ebpf logo"/>
  </a>
</p>

# 🐍 Snake eBPF Game 🐝

A nostalgic Snake game that brings back memories of the classic Nokia 3310, but with a modern twist powered by eBPF! This hobby project combines the simplicity of the beloved retro game with the powerful capabilities of eBPF kernel tracing.

## 🌟 What is this?

Remember those endless hours playing Snake on your Nokia 3310? This project brings that same nostalgic experience to your terminal, but with a unique twist: the game is powered by eBPF (Extended Berkeley Packet Filter), one of the most powerful features in the Linux kernel.

eBPF allows us to safely run programs in the kernel space, and in this game, we use it to detect system events in real-time. It's a fun way to explore what eBPF can do while enjoying a classic game!

## 🎮 Features

- **Classic Snake Gameplay**: Just like the Nokia 3310 version you remember
- **eBPF-Powered**: Uses kernel tracing to detect system events
- **Nostalgic Design**: Green snake, red food, just like the old days

## 📋 Requirements

- Linux kernel with eBPF support (5.8+ recommended)
- Go 1.24 or later
- clang
- llvm-strip
- bpftool
- Linux kernel headers: `sudo apt install linux-headers-$(uname -r)`
- libbpf development headers: `sudo apt install libbpf-dev`

## 🚀 Quick Start

### 1. Build the eBPF program

```bash
cd bpf && make && cd ..
```

### 2. Build the Go application

```bash
go mod download
go build -o snake-ebpf main.go
```

### 3. Verify your Setup

```bash
./scripts/verify-setup.sh
```

### 4. Run the game

```bash
sudo ./snake-ebpf
```


**Note**: The game requires `sudo` to attach eBPF program to the kernel.

## 🎯 How to Play

- **Arrow Keys** or **W/A/S/D** - Move the snake
- **Q** or **Ctrl+C** - Quit the game

<p align="left">
  <a href="https://github.com/gma1k/snake-ebpf">
    <img src="https://github.com/gma1k/snake-ebpf/blob/main/assets/snake-ebpf.gif" width="780" alt="snake-ebpf gif"/>
  </a>
</p>

## 🔧 How It Works

This project demonstrates the power of eBPF by combining kernel tracing with a classic game. The game uses 6 different eBPF kprobes to track system events in real-time, influencing gameplay mechanics.

### Architecture Overview

The game consists of two main components:

1. **eBPF Programs**: Run directly in the Linux kernel, tracking system events
2. **Go Application**: Handles all game logic, rendering, and reads eBPF metrics

### What eBPF Does

The eBPF program (`bpf/snake.bpf.c`) attaches 5 kprobes to kernel functions:

| eBPF Probe | Kernel Function | What It Tracks | Impact on Game |
|------------|----------------|----------------|----------------|
| `handle_execve` | `sys_enter_execve` | Process executions | Speed adjustment factor |
| `handle_file_open` | `do_sys_openat2` | File operations | Food spawning frequency |
| `handle_network_connect` | `tcp_v4_connect` | Network connections | Tracked |
| `handle_process_fork` | `_do_fork` | Process creation | Speed adjustment factor |
| `handle_context_switch` | `__schedule` | CPU context switches | Speed adjustment factor |

Additionally, eBPF calculates:
- **Event Rate**: Events per second using a hash map (`recent_events`) for pattern detection
- **Pattern Tracking**: Maintains a rolling window of events over the last 10 seconds

All metrics are stored in **BPF Maps** (shared memory between kernel and userspace):
- `execve_counter` - Process execution count
- `file_ops_counter` - File operation count
- `network_counter` - Network connection count
- `process_counter` - Process creation count
- `context_switch_counter` - CPU activity indicator
- `event_rate` - Events per second
- `recent_events` - Time-bucketed event tracking (hash map)

### What Go Uses from eBPF

Every game tick (~350ms), Go reads all eBPF metrics and uses them for:

1. **Speed Adjustment** (5 eBPF factors):
   - Base speed: 350ms
   - Score-based: -1ms per food eaten
   - Execve-based: -0.5ms per execve call
   - Process-based: -0.33ms per process created
   - Event rate: -1ms per event/second
   - System load: -0.00067ms per 1500 context switches
   - All factors combined reduce the interval

2. **Food Spawning**:
   - Base interval: 15 seconds
   - File operations reduce interval (more file ops = faster spawning)
   - Minimum: 5 seconds
   - Go spawns extra food when file operations are detected

### Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│                      KERNEL                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  System Events Happen:                                  │
│  ├─ User runs: ls, cat, echo                            │
│  │  └─→ handle_execve() → execve_counter++              │
│  │                                                      │
│  ├─ File operations: open, read, write                  │
│  │  └─→ handle_file_open() → file_ops_counter++         │
│  │                                                      │
│  ├─ Network connections: curl, wget, ssh                │
│  │  └─→ handle_network_connect() → network_counter++    │
│  │                                                      │
│  ├─ Process creation: fork, clone                       │
│  │  └─→ handle_process_fork() → process_counter++       │
│  │                                                      │
│  └─ CPU activity: task switching                        │
│     └─→ handle_context_switch() → context_switch++      │
│                                                         │
│  All events also update:                                │
│  - recent_events map (pattern tracking)                 │
│  - event_rate (events per second calculation)           │
│                                                         │
└─────────────────────────────────────────────────────────┘
                        │
                        │ BPF Maps
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   USERSPACE                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Every 350ms (game tick):                               │
│                                                         │
│  1. READ eBPF METRICS:                                  │
│     ├─ execveMap.Lookup() → execveCount                 │
│     ├─ fileOpsMap.Lookup() → fileOpsCount               │
│     ├─ networkMap.Lookup() → networkCount               │
│     ├─ processMap.Lookup() → processCount               │
│     ├─ contextSwitchMap.Lookup() → contextSwitchCount   │
│     └─ eventRateMap.Lookup() → eventRate                │
│                                                         │
│  2. USE eBPF DATA FOR GAMEPLAY:                         │
│                                                         │
│     A. FOOD SPAWNING (fileOpsCount):                    │
│        - Calculate spawn interval based on file ops     │
│        - More file ops = food spawns faster             │
│        - Go calls game.spawnFood() when interval passes │
│                                                         │
│     B. SPEED CALCULATION:                 │
│        - Base: 350ms                                    │
│        - Score: -1ms per food (Go)                      │
│        - Execve: -0.5ms per execve (eBPF)               │
│        - Process: -0.33ms per process (eBPF)            │
│        - Event Rate: -1ms per event/sec (eBPF)          │
│        - Load: -0.00067ms per 1500 switches (eBPF)      │
│        - Combined: newInterval = base - all reductions  │
│        - Go updates game ticker with new speed          │
│                                                         │
│  3. GAME LOGIC:                                         │
│     - Move snake (Go)                                   │
│     - Check collisions (Go)                             │
│     - Handle food eating (Go)                           │
│     - Grow snake (Go)                                   │
│     - Render display (Go)                               │
│     - Handle input (Go)                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘

```
**In Summary**: eBPF tracks system activity and provides metrics. Go reads those metrics and uses them to adjust game speed and food spawning.

## 💡 Why This Project?

This is a hobby project born from curiosity about eBPF and nostalgia for classic games. eBPF is incredibly powerful, it's used for monitoring, security, networking, and more. But it can also be fun! This project shows that kernel programming doesn't have to be intimidating, and sometimes the best way to learn is by building something you enjoy.

## 🤝 Contributing

This is a hobby project, but contributions are welcome! Feel free to:
- Report bugs
- Suggest improvements
- Submit pull requests

---

**Enjoy the game and happy coding!** 🐍🐝
