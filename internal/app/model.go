package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoldyzdk/sniff/internal/discovery"
)

type Scanner interface {
	ScanListeningTCP(ctx context.Context) ([]discovery.Listener, error)
}

type TickScheduler func(d time.Duration) tea.Cmd

type Config struct {
	Scanner       Scanner
	TickEvery     time.Duration
	TickScheduler TickScheduler
}

type AutoRefreshMsg struct{}

type refreshResultMsg struct {
	listeners []discovery.Listener
	err       error
}

type Model struct {
	scanner       Scanner
	tickEvery     time.Duration
	tickScheduler TickScheduler

	listeners []discovery.Listener
	cursor    int
	lastError error
	width     int
	selected  rowKey
}

type rowKey struct {
	port int
	pid  int
}

func NewModel(cfg Config) Model {
	tickEvery := cfg.TickEvery
	if tickEvery <= 0 {
		tickEvery = 2 * time.Second
	}
	tickScheduler := cfg.TickScheduler
	if tickScheduler == nil {
		tickScheduler = func(d time.Duration) tea.Cmd {
			return tea.Tick(d, func(time.Time) tea.Msg {
				return AutoRefreshMsg{}
			})
		}
	}
	return Model{
		scanner:       cfg.Scanner,
		tickEvery:     tickEvery,
		tickScheduler: tickScheduler,
		width:         100,
	}
}

func (m Model) Init() tea.Cmd {
	return m.fetchListenersCmd()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case refreshResultMsg:
		m.listeners = msg.listeners
		m.lastError = msg.err
		m.restoreSelection()
		if m.cursor >= len(m.listeners) {
			if len(m.listeners) == 0 {
				m.cursor = 0
			} else {
				m.cursor = len(m.listeners) - 1
			}
		}
		m.captureSelection()
		return m, m.scheduleTick()
	case AutoRefreshMsg:
		return m, m.fetchListenersCmd()
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
		}
		return m, nil
	case tea.KeyMsg:
		if len(msg.Runes) == 1 && msg.Runes[0] == 'r' {
			return m, m.fetchListenersCmd()
		}
		switch msg.String() {
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
			m.captureSelection()
		case "down":
			if m.cursor < len(m.listeners)-1 {
				m.cursor++
			}
			m.captureSelection()
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-7s %-18s %-7s %-14s %-11s %-10s %-11s\n",
		"PORT", "PROCESS", "PID", "PROJECT", "FRAMEWORK", "UPTIME", "STATUS"))
	for i, item := range m.listeners {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		b.WriteString(fmt.Sprintf("%s%-7s %-18s %-7d %-14s %-11s %-10s %-11s\n",
			prefix,
			fmt.Sprintf(":%d", item.Port),
			truncate(item.Process, 18),
			item.PID,
			truncate(item.Project, 14),
			truncate(item.Framework, 11),
			truncate(item.Uptime, 10),
			truncate("● "+item.Status, 11),
		))
	}
	b.WriteString("\n")
	b.WriteString(m.renderDetails())
	if m.lastError != nil {
		b.WriteString("\nerror: ")
		b.WriteString(m.lastError.Error())
		b.WriteRune('\n')
	}
	b.WriteString("\n[up/down] navigate  [r] refresh  [q] quit\n")
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func (m Model) IsTableFocused() bool {
	return true
}

func (m Model) Cursor() int {
	return m.cursor
}

func (m Model) Listeners() []discovery.Listener {
	cp := make([]discovery.Listener, len(m.listeners))
	copy(cp, m.listeners)
	return cp
}

func (m Model) fetchListenersCmd() tea.Cmd {
	return func() tea.Msg {
		if m.scanner == nil {
			return refreshResultMsg{listeners: nil, err: nil}
		}
		listeners, err := m.scanner.ScanListeningTCP(context.Background())
		return refreshResultMsg{
			listeners: listeners,
			err:       err,
		}
	}
}

func (m Model) scheduleTick() tea.Cmd {
	return m.tickScheduler(m.tickEvery)
}

func (m Model) renderDetails() string {
	if len(m.listeners) == 0 || m.cursor < 0 || m.cursor >= len(m.listeners) {
		return "Details\n- no row selected\n"
	}
	item := m.listeners[m.cursor]
	if m.width < 80 {
		return fmt.Sprintf(
			"Details (compact)\nPID:%d USER:%s CMD:%s\n",
			item.PID,
			truncate(item.User, 10),
			truncate(item.Command, 38),
		)
	}
	return fmt.Sprintf(
		"Details\nPID: %d\nCommand: %s\nExecutable: %s\nUser: %s\n",
		item.PID,
		item.Command,
		item.Executable,
		item.User,
	)
}

func (m *Model) captureSelection() {
	if len(m.listeners) == 0 || m.cursor < 0 || m.cursor >= len(m.listeners) {
		m.selected = rowKey{}
		return
	}
	row := m.listeners[m.cursor]
	m.selected = rowKey{port: row.Port, pid: row.PID}
}

func (m *Model) restoreSelection() {
	if m.selected == (rowKey{}) {
		return
	}
	for i, row := range m.listeners {
		if row.Port == m.selected.port && row.PID == m.selected.pid {
			m.cursor = i
			return
		}
	}
}
