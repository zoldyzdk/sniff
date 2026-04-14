package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoldyzdk/sniff/internal/action"
	"github.com/zoldyzdk/sniff/internal/discovery"
	"github.com/zoldyzdk/sniff/internal/refresh"
)

type Scanner interface {
	ScanListeningTCP(ctx context.Context) ([]discovery.Listener, error)
}

type TickScheduler func(d time.Duration) tea.Cmd

type Stopper interface {
	GracefulStop(ctx context.Context, target action.Target) action.Result
	ForceStop(ctx context.Context, target action.Target) error
}

type Config struct {
	Scanner       Scanner
	Stopper       Stopper
	RebindWindow  time.Duration
	Now           func() time.Time
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
	stopper       Stopper
	tickEvery     time.Duration
	tickScheduler TickScheduler
	now           func() time.Time
	refreshCoord  *refresh.Coordinator

	listeners            []discovery.Listener
	cursor               int
	lastError            error
	width                int
	selected             rowKey
	statusMsg            string
	awaitingConfirm      bool
	pendingTarget        action.Target
	history              []string
	forceAvailable       bool
	awaitingForceConfirm bool
	searching            bool
	search               string
	theme                theme
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
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return Model{
		scanner:       cfg.Scanner,
		stopper:       cfg.Stopper,
		tickEvery:     tickEvery,
		tickScheduler: tickScheduler,
		now:           nowFn,
		refreshCoord:  refresh.NewCoordinator(cfg.RebindWindow),
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
		m.applyRebindEvents()
		m.restoreSelection()
		visible := m.visibleListeners()
		if m.cursor >= len(visible) {
			if len(m.listeners) == 0 {
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
		if m.awaitingConfirm {
			if len(msg.Runes) == 1 && msg.Runes[0] == 'y' {
				m.applyGracefulStop()
				return m, nil
			}
			if len(msg.Runes) == 1 && msg.Runes[0] == 'n' {
				m.awaitingConfirm = false
				m.statusMsg = "graceful stop cancelled"
				return m, nil
			}
		}
		if m.awaitingForceConfirm {
			if len(msg.Runes) == 1 && msg.Runes[0] == 'y' {
				m.applyForceStop()
				return m, nil
			}
			if len(msg.Runes) == 1 && msg.Runes[0] == 'n' {
				m.awaitingForceConfirm = false
				m.statusMsg = "force kill cancelled"
				return m, nil
			}
		}
		if len(msg.Runes) == 1 && msg.Runes[0] == 's' {
			row := m.selectedRow()
			if row != nil && row.Restricted {
				m.statusMsg = "action blocked: rerun with elevated privileges"
			} else {
				m.awaitingConfirm = true
				if row != nil {
					m.pendingTarget = action.Target{PID: row.PID, Port: row.Port}
					m.statusMsg = fmt.Sprintf("confirm graceful stop for pid=%d on :%d [y/n]", row.PID, row.Port)
				}
			}
			return m, nil
		}
		if len(msg.Runes) == 1 && msg.Runes[0] == 'f' && m.forceAvailable {
			m.awaitingForceConfirm = true
			m.statusMsg = "force kill is destructive, confirm [y/n]"
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
			truncate(renderProcess(item), 18),
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
	if len(m.history) > 0 {
		b.WriteString("\nRecent actions\n")
		for _, line := range m.history {
			b.WriteString("- ")
			b.WriteString(line)
			b.WriteString("\n")
		}
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
		"%s\nPID: %d\nCommand: %s\nExecutable: %s\nUser: %s\nContainer: %s\n%s",
		m.theme.detailsTitle.Render("Details"),
		item.PID,
		item.Command,
		item.Executable,
		item.User,
		containerHintDisplay(item.ContainerHint),
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

func renderProcess(item discovery.Listener) string {
	if strings.TrimSpace(item.ContainerHint) == "" {
		return item.Process
	}
	return item.Process + " (" + item.ContainerHint + ")"
}

func containerHintDisplay(hint string) string {
	if strings.TrimSpace(hint) == "" {
		return "-"
	}
	return hint
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

func (m *Model) applyGracefulStop() {
	m.awaitingConfirm = false
	if m.stopper == nil {
		m.statusMsg = "graceful stop succeeded"
		m.recordAction(fmt.Sprintf("SIGTERM pid=%d port=%d success", m.pendingTarget.PID, m.pendingTarget.Port))
		return
	}
	result := m.stopper.GracefulStop(context.Background(), m.pendingTarget)
	if result.Err != nil {
		m.statusMsg = "graceful stop failed"
		m.recordAction(fmt.Sprintf("SIGTERM pid=%d port=%d error", m.pendingTarget.PID, m.pendingTarget.Port))
		return
	}
	if result.NeedsForce {
		m.statusMsg = "graceful stop incomplete: port still bound (press [f] to force kill)"
		m.forceAvailable = true
		m.recordAction(fmt.Sprintf("SIGTERM pid=%d port=%d pending-force", m.pendingTarget.PID, m.pendingTarget.Port))
		return
	}
	if m.refreshCoord != nil {
		m.refreshCoord.MarkTargeted(m.pendingTarget.Port, m.now())
	}
	m.forceAvailable = false
	m.statusMsg = "graceful stop succeeded"
	m.recordAction(fmt.Sprintf("SIGTERM pid=%d port=%d success", m.pendingTarget.PID, m.pendingTarget.Port))
}

func (m *Model) recordAction(line string) {
	m.history = append([]string{line}, m.history...)
	if len(m.history) > 5 {
		m.history = m.history[:5]
	}
}

func (m *Model) applyRebindEvents() {
	if m.refreshCoord == nil {
		return
	}
	ev := m.refreshCoord.Observe(m.listeners, m.now())
	if len(ev.ReboundPorts) == 0 {
		return
	}
	m.statusMsg = fmt.Sprintf("warning: likely restart loop; port :%d rebound quickly", ev.ReboundPorts[0])
	for _, port := range ev.ReboundPorts {
		m.recordAction(fmt.Sprintf("rebound :%d detected (likely restart loop)", port))
	}
}

func (m *Model) applyForceStop() {
	m.awaitingForceConfirm = false
	if m.stopper == nil {
		m.statusMsg = "force kill succeeded"
		m.recordAction(fmt.Sprintf("SIGKILL pid=%d port=%d success", m.pendingTarget.PID, m.pendingTarget.Port))
		m.forceAvailable = false
		return
	}
	if err := m.stopper.ForceStop(context.Background(), m.pendingTarget); err != nil {
		m.statusMsg = "force kill failed"
		m.recordAction(fmt.Sprintf("SIGKILL pid=%d port=%d error", m.pendingTarget.PID, m.pendingTarget.Port))
		return
	}
	m.statusMsg = "force kill succeeded"
	m.recordAction(fmt.Sprintf("SIGKILL pid=%d port=%d success", m.pendingTarget.PID, m.pendingTarget.Port))
	m.forceAvailable = false
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
