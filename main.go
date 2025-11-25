package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	POLL_INTERVAL = 350 * time.Millisecond
)

type Position struct {
	X, Y int
}

type Game struct {
	snake           []Position
	direction       Position
	food            Position
	score           int
	gameOver        bool
	width           int
	height          int
	termWidth       int
	termHeight      int
	lastFoodSpawn   time.Time
	ebpfMetrics     eBPFMetrics
}

type eBPFMetrics struct {
	execveCount        uint64
	fileOpsCount       uint64
	networkCount       uint64
	processCount       uint64
	contextSwitchCount uint64
	eventRate          uint64
	lastUpdate         time.Time
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: This program must be run with sudo\n")
		fmt.Fprintf(os.Stderr, "Please run: sudo ./snake-ebpf\n")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	collection, err := loadEBPF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load eBPF program: %v\n", err)
		os.Exit(1)
	}
	defer collection.Close()

	links, err := attachAllKprobes(collection)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobes: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for _, link := range links {
			if link != nil {
				link.Close()
			}
		}
	}()

	setupTerminal()
	defer restoreTerminal()

	termWidth, termHeight := getTerminalSize()
	
	gameWidth := (termWidth * 3) / 10
	gameHeight := (termHeight * 3) / 10
	
	if gameWidth < 18 {
		gameWidth = 18
	}
	if gameWidth > 32 {
		gameWidth = 32
	}
	if gameHeight < 8 {
		gameHeight = 8
	}
	if gameHeight > 16 {
		gameHeight = 16
	}
	
	if termWidth < gameWidth+4 || termHeight < gameHeight+4 {
		gameWidth = 20
		gameHeight = 10
	}

	fmt.Println("eBPF program attached! Starting Snake game...")
	time.Sleep(1 * time.Second)

	startX := gameWidth / 2
	startY := gameHeight / 2
	game := &Game{
		snake: []Position{
			{startX, startY},
			{startX - 1, startY},
			{startX - 2, startY},
		},
		direction:  Position{X: 1, Y: 0},
		gameOver:   false,
		width:      gameWidth,
		height:     gameHeight,
		termWidth:  termWidth,
		termHeight: termHeight,
		ebpfMetrics: eBPFMetrics{},
	}
	game.spawnFood()
	game.lastFoodSpawn = time.Now()

	execveMap := collection.Maps["execve_counter"]
	fileOpsMap := collection.Maps["file_ops_counter"]
	networkMap := collection.Maps["network_counter"]
	processMap := collection.Maps["process_counter"]
	contextSwitchMap := collection.Maps["context_switch_counter"]
	eventRateMap := collection.Maps["event_rate"]

	if execveMap == nil || fileOpsMap == nil || networkMap == nil ||
		processMap == nil || contextSwitchMap == nil || eventRateMap == nil {
		fmt.Fprintf(os.Stderr, "Warning: Some eBPF maps not found, using defaults\n")
	}

	game.render()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	baseInterval := POLL_INTERVAL
	currentInterval := baseInterval
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	inputChan := make(chan string, 1)
	go readInput(inputChan)

	for !game.gameOver {
		select {
		case <-sigChan:
			game.gameOver = true
			break
		case <-ticker.C:
			var key uint32 = 0
			metrics := eBPFMetrics{lastUpdate: time.Now()}
			
			if execveMap != nil {
				execveMap.Lookup(&key, unsafe.Pointer(&metrics.execveCount))
			}
			if fileOpsMap != nil {
				fileOpsMap.Lookup(&key, unsafe.Pointer(&metrics.fileOpsCount))
			}
			if networkMap != nil {
				networkMap.Lookup(&key, unsafe.Pointer(&metrics.networkCount))
			}
			if processMap != nil {
				processMap.Lookup(&key, unsafe.Pointer(&metrics.processCount))
			}
			if contextSwitchMap != nil {
				contextSwitchMap.Lookup(&key, unsafe.Pointer(&metrics.contextSwitchCount))
			}
			if eventRateMap != nil {
				eventRateMap.Lookup(&key, unsafe.Pointer(&metrics.eventRate))
			}
			
			game.ebpfMetrics = metrics
			
			if metrics.fileOpsCount > 0 {
				spawnInterval := 15 * time.Second
				fileOpsBonus := time.Duration(metrics.fileOpsCount/50) * 100 * time.Millisecond
				if fileOpsBonus > 3*time.Second {
					fileOpsBonus = 3 * time.Second
				}
				spawnInterval = spawnInterval - fileOpsBonus
				if spawnInterval < 5*time.Second {
					spawnInterval = 5 * time.Second
				}
				
				if time.Since(game.lastFoodSpawn) > spawnInterval {
					game.spawnFood()
					game.lastFoodSpawn = time.Now()
				}
			}
			
			changed := game.update()
			if changed {
				game.render()
				
				scoreSpeedReduction := time.Duration(game.score) * 1 * time.Millisecond
				
				execveSpeedReduction := time.Duration(metrics.execveCount) * 500 * time.Microsecond
				if execveSpeedReduction > 30*time.Millisecond {
					execveSpeedReduction = 30 * time.Millisecond
				}
				
				processSpeedReduction := time.Duration(metrics.processCount/3) * time.Millisecond
				if processSpeedReduction > 25*time.Millisecond {
					processSpeedReduction = 25 * time.Millisecond
				}
				
				rateSpeedReduction := time.Duration(metrics.eventRate) * 1 * time.Millisecond
				if rateSpeedReduction > 30*time.Millisecond {
					rateSpeedReduction = 30 * time.Millisecond
				}
				
				loadSpeedReduction := time.Duration(metrics.contextSwitchCount/1500) * time.Millisecond
				if loadSpeedReduction > 15*time.Millisecond {
					loadSpeedReduction = 15 * time.Millisecond
				}
				
				newInterval := baseInterval - scoreSpeedReduction - execveSpeedReduction - 
					processSpeedReduction - rateSpeedReduction - loadSpeedReduction
				
				if newInterval < 100*time.Millisecond {
					newInterval = 100 * time.Millisecond
				}
				
				if newInterval != currentInterval {
					currentInterval = newInterval
					ticker.Stop()
					ticker = time.NewTicker(currentInterval)
				}
			}

		case input := <-inputChan:
			dirChanged := false
			switch input {
			case "w", "W", "up":
				if game.direction.Y == 0 {
					game.direction = Position{X: 0, Y: -1}
					dirChanged = true
				}
			case "s", "S", "down":
				if game.direction.Y == 0 {
					game.direction = Position{X: 0, Y: 1}
					dirChanged = true
				}
			case "a", "A", "left":
				if game.direction.X == 0 {
					game.direction = Position{X: -1, Y: 0}
					dirChanged = true
				}
			case "d", "D", "right":
				if game.direction.X == 0 {
					game.direction = Position{X: 1, Y: 0}
					dirChanged = true
				}
			case "q", "Q":
				game.gameOver = true
			}
			if dirChanged {
				game.render()
			}
		}
	}

	fmt.Println("\nGame Over!")
	fmt.Printf("Final Score: %d\n", game.score)
}

func loadEBPF() (*ebpf.Collection, error) {
	bpfPaths := []string{
		"bpf/snake.bpf.o",
		"../bpf/snake.bpf.o",
		"./bpf/snake.bpf.o",
	}
	
	var spec *ebpf.CollectionSpec
	var err error
	for _, path := range bpfPaths {
		spec, err = ebpf.LoadCollectionSpec(path)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load collection spec (tried paths: %v): %w", bpfPaths, err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	var key uint32 = 0
	var value uint64 = 0
	
	mapsToInit := []string{
		"execve_counter",
		"file_ops_counter",
		"network_counter",
		"process_counter",
		"context_switch_counter",
		"event_rate",
	}
	
	for _, mapName := range mapsToInit {
		if m := collection.Maps[mapName]; m != nil {
			if err := m.Put(&key, unsafe.Pointer(&value)); err != nil {
				return nil, fmt.Errorf("initialize %s map: %w", mapName, err)
			}
		}
	}

	return collection, nil
}

func attachAllKprobes(collection *ebpf.Collection) ([]link.Link, error) {
	var links []link.Link
	
	if prog := collection.Programs["handle_execve"]; prog != nil {
		probeNames := []string{
			"sys_enter_execve",
			"__x64_sys_execve",
			"__arm64_sys_execve",
			"__s390x_sys_execve",
			"__x86_sys_execve",
		}
		for _, name := range probeNames {
			if kp, err := link.Kprobe(name, prog, nil); err == nil {
				links = append(links, kp)
				break
			}
		}
	}
	
	if prog := collection.Programs["handle_file_open"]; prog != nil {
		probeNames := []string{
			"do_sys_openat2",
			"do_sys_open",
			"__x64_sys_openat",
		}
		for _, name := range probeNames {
			if kp, err := link.Kprobe(name, prog, nil); err == nil {
				links = append(links, kp)
				break
			}
		}
	}
	
	if prog := collection.Programs["handle_network_connect"]; prog != nil {
		probeNames := []string{
			"tcp_v4_connect",
			"tcp_v6_connect",
		}
		for _, name := range probeNames {
			if kp, err := link.Kprobe(name, prog, nil); err == nil {
				links = append(links, kp)
				break
			}
		}
	}
	
	if prog := collection.Programs["handle_process_fork"]; prog != nil {
		probeNames := []string{
			"_do_fork",
			"kernel_clone",
			"__x64_sys_clone",
		}
		for _, name := range probeNames {
			if kp, err := link.Kprobe(name, prog, nil); err == nil {
				links = append(links, kp)
				break
			}
		}
	}
	
	if prog := collection.Programs["handle_context_switch"]; prog != nil {
		if kp, err := link.Kprobe("__schedule", prog, nil); err == nil {
			links = append(links, kp)
		}
	}
	
	if len(links) == 0 {
		return nil, fmt.Errorf("failed to attach any kprobes")
	}
	
	return links, nil
}

func (g *Game) update() bool {
	if g.gameOver {
		return false
	}

	if g.direction.X == 0 && g.direction.Y == 0 {
		return false
	}

	head := g.snake[0]
	newHead := Position{
		X: head.X + g.direction.X,
		Y: head.Y + g.direction.Y,
	}

	if newHead.X < 0 || newHead.X >= g.width ||
		newHead.Y < 0 || newHead.Y >= g.height {
		g.gameOver = true
		return true
	}

	for i := 0; i < len(g.snake)-1; i++ {
		segment := g.snake[i]
		if newHead.X == segment.X && newHead.Y == segment.Y {
			g.gameOver = true
			return true
		}
	}

	oldSnakeLen := len(g.snake)
	oldFood := g.food
	ateFood := false
	if newHead.X == g.food.X && newHead.Y == g.food.Y {
		g.score++
		ateFood = true
		g.spawnFood()
	} else {
		g.snake = g.snake[:len(g.snake)-1]
	}

	g.snake = append([]Position{newHead}, g.snake...)
	
	if ateFood {
		for i := 0; i < 2; i++ {
			tail := g.snake[len(g.snake)-1]
			g.snake = append(g.snake, tail)
		}
	}
	
	return oldSnakeLen != len(g.snake) || newHead != head || oldFood != g.food
}

func (g *Game) spawnFood() {
	maxAttempts := 100
	for attempt := 0; attempt < maxAttempts; attempt++ {
		g.food = Position{
			X: (int(time.Now().UnixNano()) + attempt*17) % g.width,
			Y: (int(time.Now().UnixNano()/1000) + attempt*23) % g.height,
		}
		onSnake := false
		for _, segment := range g.snake {
			if g.food.X == segment.X && g.food.Y == segment.Y {
				onSnake = true
				break
			}
		}
		if !onSnake {
			return
		}
	}
	for y := 0; y < g.height; y++ {
		for x := 0; x < g.width; x++ {
			onSnake := false
			for _, segment := range g.snake {
				if x == segment.X && y == segment.Y {
					onSnake = true
					break
				}
			}
			if !onSnake {
				g.food = Position{X: x, Y: y}
				return
			}
		}
	}
}

func (g *Game) render() {
	fmt.Print("\033[2J\033[H")
	
	gameBlockWidth := g.width*2 + 3
	gameBlockHeight := g.height + 9
	
	padLeft := (g.termWidth - gameBlockWidth) / 2
	padTop := (g.termHeight - gameBlockHeight) / 2
	
	for i := 0; i < padTop; i++ {
		fmt.Println()
	}
	
	grid := make([][]rune, g.height)
	for i := range grid {
		grid[i] = make([]rune, g.width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}

	for i, segment := range g.snake {
		if segment.Y >= 0 && segment.Y < g.height && segment.X >= 0 && segment.X < g.width {
			if i == 0 {
				grid[segment.Y][segment.X] = '●'
			} else {
				grid[segment.Y][segment.X] = '○'
			}
		}
	}

	if g.food.Y >= 0 && g.food.Y < g.height && g.food.X >= 0 && g.food.X < g.width {
		grid[g.food.Y][g.food.X] = '*'
	}

	topBorder := "┌"
	for i := 0; i < g.width*2+1; i++ {
		topBorder += "─"
	}
	topBorder += "┐"
	for i := 0; i < padLeft; i++ {
		fmt.Print(" ")
	}
	fmt.Println(topBorder)
	
	for _, row := range grid {
		for i := 0; i < padLeft; i++ {
			fmt.Print(" ")
		}
		fmt.Print("│ ")
		for _, cell := range row {
			switch cell {
			case '●', '○':
				fmt.Print("\033[32m" + string(cell) + "\033[0m ")
			case '*':
				fmt.Print("\033[31m" + string(cell) + "\033[0m ")
			default:
				fmt.Print(string(cell) + " ")
			}
		}
		fmt.Println("│")
	}
	
	bottomBorder := "└"
	for i := 0; i < g.width*2+1; i++ {
		bottomBorder += "─"
	}
	bottomBorder += "┘"
	for i := 0; i < padLeft; i++ {
		fmt.Print(" ")
	}
	fmt.Println(bottomBorder)

	level := g.score / 5
	
	infoLine1 := fmt.Sprintf("Level: %d | Score: %d | Length: %d", level, g.score, len(g.snake))
	infoLine2 := "Use Arrow keys or WASD to move"
	infoLine3 := "Q or Ctrl+C to quit"
	infoLine4 := "Powered by eBPF 🐝"
	
	infoPadLeft1 := (g.termWidth - len(infoLine1)) / 2
	infoPadLeft2 := (g.termWidth - len(infoLine2)) / 2
	infoPadLeft3 := (g.termWidth - len(infoLine3)) / 2
	
	oPosition := infoPadLeft3 + 2
	
	infoPadLeft4 := oPosition
	
	for i := 0; i < infoPadLeft1; i++ {
		fmt.Print(" ")
	}
	fmt.Println(infoLine1)
	
	fmt.Println()
	
	for i := 0; i < infoPadLeft2; i++ {
		fmt.Print(" ")
	}
	fmt.Println(infoLine2)
	
	for i := 0; i < infoPadLeft3; i++ {
		fmt.Print(" ")
	}
	fmt.Println(infoLine3)
	
	fmt.Println()
	fmt.Println()
	
	for i := 0; i < infoPadLeft4; i++ {
		fmt.Print(" ")
	}
	fmt.Println(infoLine4)
	
	os.Stdout.Sync()
}

func getTerminalSize() (int, int) {
	fd := int(os.Stdout.Fd())
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

func setupTerminal() {
	cmd := exec.Command("stty", "-echo", "-icanon", "min", "1", "time", "0")
	cmd.Stdin = os.Stdin
	cmd.Run()
	
	fd := int(os.Stdin.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err == nil {
		termios.Lflag &^= unix.ECHO | unix.ICANON
		termios.Cc[unix.VMIN] = 1
		termios.Cc[unix.VTIME] = 0
		unix.IoctlSetTermios(fd, unix.TCSETS, termios)
	}
}

func restoreTerminal() {
	cmd := exec.Command("stty", "echo", "icanon")
	cmd.Stdin = os.Stdin
	cmd.Run()
	
	fd := int(os.Stdin.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err == nil {
		termios.Lflag |= unix.ECHO | unix.ICANON | unix.ISIG
		unix.IoctlSetTermios(fd, unix.TCSETS, termios)
	}
}

func readInput(ch chan<- string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		char, err := reader.ReadByte()
		if err != nil {
			close(ch)
			return
		}
		
		if char == '\033' || char == 0x1b {
			peeked, _ := reader.Peek(2)
			if len(peeked) >= 2 && peeked[0] == '[' {
				reader.ReadByte()
				dir, err := reader.ReadByte()
				if err != nil {
					continue
				}
				var direction string
				switch dir {
				case 'A':
					direction = "up"
				case 'B':
					direction = "down"
				case 'C':
					direction = "right"
				case 'D':
					direction = "left"
				default:
					continue
				}
				select {
				case ch <- direction:
				default:
				}
				continue
			}
		}
		
		input := string(char)
		if char >= 'A' && char <= 'Z' {
			input = string(char + 32)
		}
		
		select {
		case ch <- input:
		default:
		}
	}
}
