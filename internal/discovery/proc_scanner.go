package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Listener struct {
	Port       int
	Process    string
	PID        int
	Command    string
	Executable string
	User       string
	Project    string
	Framework  string
	Uptime     string
	Status     string
}

type ProcScanner struct {
	procRoot string
}

func NewProcScanner(procRoot string) *ProcScanner {
	return &ProcScanner{procRoot: procRoot}
}

func (s *ProcScanner) ScanListeningTCP(ctx context.Context) ([]Listener, error) {
	inodesByPort := map[int]string{}
	for _, table := range []string{"tcp", "tcp6"} {
		tableInodes, err := readListeningInodes(filepath.Join(s.procRoot, "net", table))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for port, inode := range tableInodes {
			if _, exists := inodesByPort[port]; !exists {
				inodesByPort[port] = inode
			}
		}
	}
	pidByInode, err := readPidBySocketInode(ctx, s.procRoot)
	if err != nil {
		return nil, err
	}

	listeners := make([]Listener, 0, len(inodesByPort))
	for port, inode := range inodesByPort {
		pid, ok := pidByInode[inode]
		if !ok {
			continue
		}
		meta := readProcessMeta(s.procRoot, pid)
		listeners = append(listeners, Listener{
			Port:       port,
			Process:    meta.process,
			PID:        pid,
			Command:    meta.command,
			Executable: meta.executable,
			User:       meta.user,
			Project:    meta.project,
			Framework:  meta.framework,
			Uptime:     meta.uptime,
			Status:     "healthy",
		})
	}

	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Port == listeners[j].Port {
			return listeners[i].PID < listeners[j].PID
		}
		return listeners[i].Port < listeners[j].Port
	})
	return listeners, nil
}

type processMeta struct {
	process    string
	command    string
	executable string
	user       string
	project    string
	framework  string
	uptime     string
}

func readProcessMeta(procRoot string, pid int) processMeta {
	meta := processMeta{
		process:    "unknown",
		command:    "-",
		executable: "-",
		user:       "-",
		project:    "-",
		framework:  "-",
		uptime:     "-",
	}

	pidStr := strconv.Itoa(pid)
	commPath := filepath.Join(procRoot, pidStr, "comm")
	if raw, err := os.ReadFile(commPath); err == nil {
		comm := strings.TrimSpace(string(raw))
		if comm != "" {
			meta.process = comm
		}
	}

	cmdline := ""
	cmdlinePath := filepath.Join(procRoot, pidStr, "cmdline")
	if raw, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline = strings.ReplaceAll(string(raw), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline != "" {
			meta.command = cmdline
		}
	}
	exePath := filepath.Join(procRoot, pidStr, "exe")
	if exe, err := os.Readlink(exePath); err == nil && strings.TrimSpace(exe) != "" {
		meta.executable = exe
	}

	cwdPath := filepath.Join(procRoot, pidStr, "cwd")
	if cwd, err := os.Readlink(cwdPath); err == nil {
		base := filepath.Base(cwd)
		if base != "" && base != "." && base != "/" {
			meta.project = base
		}
	}

	meta.framework = detectFramework(meta.process + " " + cmdline)
	meta.uptime = readUptime(procRoot, pidStr)
	if info, err := os.Stat(filepath.Join(procRoot, pidStr)); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			meta.user = strconv.FormatUint(uint64(stat.Uid), 10)
		}
	}
	return meta
}

func detectFramework(s string) string {
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "next"):
		return "Next.js"
	case strings.Contains(lower, "vite"):
		return "Vite"
	case strings.Contains(lower, "node"):
		return "Node.js"
	case strings.Contains(lower, "bun"):
		return "Bun"
	case strings.Contains(lower, "go"):
		return "Go"
	default:
		return "-"
	}
}

func readUptime(procRoot, pid string) string {
	pidDir := filepath.Join(procRoot, pid)
	info, err := os.Stat(pidDir)
	if err != nil {
		return "-"
	}
	d := time.Since(info.ModTime())
	if d < 0 {
		return "0s"
	}
	return formatDurationShort(d)
}

func formatDurationShort(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	min := sec / 60
	if min < 60 {
		return fmt.Sprintf("%dm %ds", min, sec%60)
	}
	hour := min / 60
	if hour < 24 {
		return fmt.Sprintf("%dh %dm", hour, min%60)
	}
	day := hour / 24
	return fmt.Sprintf("%dd %dh", day, hour%24)
}

func readListeningInodes(tcpPath string) (map[int]string, error) {
	file, err := os.Open(tcpPath)
	if err != nil {
		return nil, fmt.Errorf("open tcp table: %w", err)
	}
	defer file.Close()

	inodesByPort := map[int]string{}
	scanner := bufio.NewScanner(file)
	isHeader := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if isHeader {
			isHeader = false
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 10 {
			continue
		}
		if parts[3] != "0A" {
			continue
		}
		portHex := strings.Split(parts[1], ":")
		if len(portHex) != 2 {
			continue
		}
		port, err := strconv.ParseInt(portHex[1], 16, 32)
		if err != nil {
			continue
		}
		inodesByPort[int(port)] = parts[9]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan tcp table: %w", err)
	}
	return inodesByPort, nil
}

func readPidBySocketInode(ctx context.Context, procRoot string) (map[string]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}
	pidByInode := map[string]int{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdPath := filepath.Join(procRoot, entry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fdEntry := range fdEntries {
			linkPath := filepath.Join(fdPath, fdEntry.Name())
			linkTarget, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(linkTarget)
			if !ok {
				continue
			}
			if _, exists := pidByInode[inode]; !exists {
				pidByInode[inode] = pid
			}
		}
	}
	return pidByInode, nil
}

func parseSocketInode(linkTarget string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(linkTarget, prefix) || !strings.HasSuffix(linkTarget, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(linkTarget, prefix), "]"), true
}
