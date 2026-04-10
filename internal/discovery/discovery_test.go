package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcScannerScanListeningTCP_FindsListeningPortOwner(t *testing.T) {
	procRoot := t.TempDir()

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000   1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000   1000        0 12346 1 0000000000000000 100 0 0 10 0
`
	if err := os.MkdirAll(filepath.Join(procRoot, "net"), 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "net", "tcp"), []byte(tcpContent), 0o644); err != nil {
		t.Fatalf("write tcp: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(procRoot, "123", "fd"), 0o755); err != nil {
		t.Fatalf("mkdir pid fd: %v", err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(procRoot, "123", "fd", "7")); err != nil {
		t.Fatalf("symlink socket fd: %v", err)
	}

	scanner := NewProcScanner(procRoot)
	got, err := scanner.ScanListeningTCP(context.Background())
	if err != nil {
		t.Fatalf("scan listening tcp: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 listening socket, got %d", len(got))
	}
	if got[0].Port != 3000 {
		t.Fatalf("expected port 3000, got %d", got[0].Port)
	}
	if got[0].PID != 123 {
		t.Fatalf("expected pid 123, got %d", got[0].PID)
	}
}

func TestProcScannerScanListeningTCP_FindsIPv6ListeningPortOwner(t *testing.T) {
	procRoot := t.TempDir()

	tcp6Content := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 99999 1 0000000000000000 100 0 0 10 0
`
	if err := os.MkdirAll(filepath.Join(procRoot, "net"), 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "net", "tcp6"), []byte(tcp6Content), 0o644); err != nil {
		t.Fatalf("write tcp6: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(procRoot, "456", "fd"), 0o755); err != nil {
		t.Fatalf("mkdir pid fd: %v", err)
	}
	if err := os.Symlink("socket:[99999]", filepath.Join(procRoot, "456", "fd", "9")); err != nil {
		t.Fatalf("symlink socket fd: %v", err)
	}

	scanner := NewProcScanner(procRoot)
	got, err := scanner.ScanListeningTCP(context.Background())
	if err != nil {
		t.Fatalf("scan listening tcp: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 listening socket, got %d", len(got))
	}
	if got[0].Port != 3000 {
		t.Fatalf("expected port 3000, got %d", got[0].Port)
	}
	if got[0].PID != 456 {
		t.Fatalf("expected pid 456, got %d", got[0].PID)
	}
}

func TestProcScannerScanListeningTCP_EnrichesProcessMetadata(t *testing.T) {
	procRoot := t.TempDir()

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:13E1 00000000:0000 0A 00000000:00000000 00:00000000 00000000   1000        0 55555 1 0000000000000000 100 0 0 10 0
`
	if err := os.MkdirAll(filepath.Join(procRoot, "net"), 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "net", "tcp"), []byte(tcpContent), 0o644); err != nil {
		t.Fatalf("write tcp: %v", err)
	}

	pidDir := filepath.Join(procRoot, "222")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatalf("mkdir pid fd: %v", err)
	}
	if err := os.Symlink("socket:[55555]", filepath.Join(pidDir, "fd", "5")); err != nil {
		t.Fatalf("symlink socket fd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("node\n"), 0o644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("vite\x00dev\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	projectDir := filepath.Join(procRoot, "workspace", "my-app")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	if err := os.Symlink(projectDir, filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatalf("symlink cwd: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(pidDir, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes pid dir: %v", err)
	}

	scanner := NewProcScanner(procRoot)
	got, err := scanner.ScanListeningTCP(context.Background())
	if err != nil {
		t.Fatalf("scan listening tcp: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(got))
	}

	row := got[0]
	if row.Port != 5089 {
		t.Fatalf("expected port 5089, got %d", row.Port)
	}
	if row.Process != "node" {
		t.Fatalf("expected process node, got %q", row.Process)
	}
	if row.Project != "my-app" {
		t.Fatalf("expected project my-app, got %q", row.Project)
	}
	if row.Framework != "Vite" {
		t.Fatalf("expected framework Vite, got %q", row.Framework)
	}
	if !strings.Contains(row.Uptime, "m") {
		t.Fatalf("expected minute-scale uptime, got %q", row.Uptime)
	}
}
