package app

import (
	"context"
	"fmt"
	"strconv"
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
	statusMsg string
	searching bool
	search    string
	theme     theme
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
		theme:         defaultTheme(),
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
		visible := m.visibleListeners()
		if m.cursor >= len(visible) {
			if len(visible) == 0 {
				m.cursor = 0
			} else {
				m.cursor = len(visible) - 1
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
		if m.searching {
			switch msg.String() {
			case "esc":
				m.searching = false
				m.search = ""
				m.cursor = 0
				return m, nil
			case "enter":
				m.searching = false
				return m, nil
			case "backspace":
				if len(m.search) > 0 {
					m.search = m.search[:len(m.search)-1]
				}
				m.cursor = 0
				return m, nil
			}
			if len(msg.Runes) == 1 && msg.Runes[0] >= 32 {
				m.search += string(msg.Runes[0])
				m.cursor = 0
				return m, nil
			}
		}
		if len(msg.Runes) == 1 && msg.Runes[0] == '/' {
			m.searching = true
			return m, nil
		}
		if len(msg.Runes) == 1 && msg.Runes[0] == 'r' {
			return m, m.fetchListenersCmd()
		}
		if len(msg.Runes) == 1 && msg.Runes[0] == 's' {
			row := m.selectedRow()
			if row != nil && row.Restricted {
				m.statusMsg = "action blocked: rerun with elevated privileges"
			} else {
				m.statusMsg = "action accepted"
			}
			return m, nil
		}
		visible := m.visibleListeners()
		switch msg.String() {
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
			m.captureSelection()
		case "down":
			if m.cursor < len(visible)-1 {
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
	b.WriteString(m.theme.searchLabel.Render(fmt.Sprintf("Search: %s", m.search)))
	b.WriteString("\n")
	b.WriteString(m.theme.header.Render(fmt.Sprintf("%-7s %-18s %-7s %-14s %-11s %-10s %-11s",
		"PORT", "PROCESS", "PID", "PROJECT", "FRAMEWORK", "UPTIME", "STATUS")))
	b.WriteString("\n")
	visible := m.visibleListeners()
	for i, item := range visible {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		row := fmt.Sprintf("%s%-7s %-18s %-7d %-14s %-11s %-10s %-11s",
			prefix,
			fmt.Sprintf(":%d", item.Port),
			truncate(item.Process, 18),
			item.PID,
			truncate(item.Project, 14),
			truncate(item.Framework, 11),
			truncate(item.Uptime, 10),
			truncate(renderStatus(item), 11),
		)
		if i == m.cursor {
			b.WriteString(m.theme.selectedRow.Render(row))
		} else {
			b.WriteString(m.theme.normalRow.Render(row))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.renderDetails())
	if strings.TrimSpace(m.statusMsg) != "" {
		b.WriteString("\n")
		if strings.Contains(strings.ToLower(m.statusMsg), "warning") || strings.Contains(strings.ToLower(m.statusMsg), "blocked") {
			b.WriteString(m.theme.warning.Render(m.statusMsg))
		} else {
			b.WriteString(m.theme.success.Render(m.statusMsg))
		}
		b.WriteString("\n")
	}
	if m.lastError != nil {
		b.WriteString("\nerror: ")
		b.WriteString(m.lastError.Error())
		b.WriteRune('\n')
	}
	if m.searching {
		b.WriteString("\n")
		b.WriteString(m.theme.footer.Render("[up/down] navigate  [type] filter  [backspace] delete  [esc] clear  [q] quit"))
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
		b.WriteString(m.theme.footer.Render("[up/down] navigate  [/] search  [r] refresh  [q] quit"))
		b.WriteString("\n")
	}
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
	item, ok := m.rowAtCursor()
	if !ok {
		return "Details\n- no row selected\n"
	}
	if m.width < 80 {
		return fmt.Sprintf(
			"%s\nPID:%d USER:%s CMD:%s\n",
			m.theme.detailsTitle.Render("Details (compact)"),
			item.PID,
			truncate(item.User, 10),
			truncate(item.Command, 38),
		)
	}
	return fmt.Sprintf(
		"%s\nPID: %d\nCommand: %s\nExecutable: %s\nUser: %s\n%s",
		m.theme.detailsTitle.Render("Details"),
		item.PID,
		item.Command,
		item.Executable,
		item.User,
		restrictionGuidance(item),
	)
}

func (m *Model) captureSelection() {
	row, ok := m.rowAtCursor()
	if !ok {
		m.selected = rowKey{}
		return
	}
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

func (m Model) selectedRow() *discovery.Listener {
	row, ok := m.rowAtCursor()
	if !ok {
		return nil
	}
	return &row
}

func renderStatus(item discovery.Listener) string {
	if item.Restricted {
		return "● locked"
	}
	return "● " + item.Status
}

func restrictionGuidance(item discovery.Listener) string {
	if !item.Restricted {
		return ""
	}
	return "Guidance: rerun with elevated privileges to control this process.\n"
}

func (m Model) visibleListeners() []discovery.Listener {
	if strings.TrimSpace(m.search) == "" {
		return m.listeners
	}
	query := strings.ToLower(strings.TrimSpace(m.search))
	filtered := make([]discovery.Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		if strings.Contains(strings.ToLower(strconv.Itoa(l.Port)), query) ||
			strings.Contains(strings.ToLower(l.Process), query) ||
			strings.Contains(strings.ToLower(l.Command), query) ||
			strings.Contains(strings.ToLower(l.Executable), query) {
			filtered = append(filtered, l)
		}
	}
	return filtered
}

func (m Model) rowAtCursor() (discovery.Listener, bool) {
	visible := m.visibleListeners()
	if len(visible) == 0 || m.cursor < 0 || m.cursor >= len(visible) {
		return discovery.Listener{}, false
	}
	return visible[m.cursor], true
}
