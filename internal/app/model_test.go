package app_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoldyzdk/sniff/internal/action"
	"github.com/zoldyzdk/sniff/internal/app"
	"github.com/zoldyzdk/sniff/internal/discovery"
)

type fakeScanner struct {
	results [][]discovery.Listener
	calls   int
}

type fakeStopper struct {
	mu         sync.Mutex
	targets    []action.Target
	result     action.Result
	forceCalls []action.Target
	forceErr   error
}

func (f *fakeStopper) GracefulStop(_ context.Context, target action.Target) action.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = append(f.targets, target)
	return f.result
}

func (f *fakeStopper) ForceStop(_ context.Context, target action.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forceCalls = append(f.forceCalls, target)
	return f.forceErr
}

func (f *fakeScanner) ScanListeningTCP(context.Context) ([]discovery.Listener, error) {
	idx := f.calls
	f.calls++
	if idx >= len(f.results) {
		return nil, nil
	}
	return f.results[idx], nil
}

func runCmd(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	return cmd()
}

func TestModelInitLoadsRowsAndStartsTableFocused(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{Port: 3000, PID: 1001},
				{Port: 8080, PID: 1002},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return func() tea.Msg { return app.AutoRefreshMsg{} }
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, cmd := model.Update(initMsg)
	model = updated.(app.Model)
	_ = cmd

	if len(model.Listeners()) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(model.Listeners()))
	}
	if !model.IsTableFocused() {
		t.Fatal("expected table to be focused on startup")
	}
}

func TestModelArrowNavigationMovesSelection(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{Port: 3000, PID: 1001},
				{Port: 8080, PID: 1002},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(app.Model)
	if model.Cursor() != 1 {
		t.Fatalf("expected cursor to move down to 1, got %d", model.Cursor())
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(app.Model)
	if model.Cursor() != 0 {
		t.Fatalf("expected cursor to move up to 0, got %d", model.Cursor())
	}
}

func TestModelManualRefreshRequestsFreshScan(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001}},
			{{Port: 5173, PID: 2222}},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, cmd := model.Update(tea.KeyMsg{Runes: []rune{'r'}})
	model = updated.(app.Model)
	refreshMsg := runCmd(t, cmd)
	updated, _ = model.Update(refreshMsg)
	model = updated.(app.Model)

	if got := model.Listeners(); len(got) != 1 || got[0].Port != 5173 {
		t.Fatalf("expected refreshed listener on 5173, got %+v", got)
	}
}

func TestModelAutoRefreshMessageTriggersRescan(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001}},
			{{Port: 5173, PID: 2222}},
		},
	}
	tickScheduled := 0
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			tickScheduled++
			return func() tea.Msg { return app.AutoRefreshMsg{} }
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, cmd := model.Update(app.AutoRefreshMsg{})
	model = updated.(app.Model)

	msg := runCmd(t, cmd)
	updated, _ = model.Update(msg)
	model = updated.(app.Model)

	if got := model.Listeners(); len(got) != 1 || got[0].Port != 5173 {
		t.Fatalf("expected auto-refreshed listener on 5173, got %+v", got)
	}
	if tickScheduled < 2 {
		t.Fatalf("expected tick to be scheduled at least twice, got %d", tickScheduled)
	}
}

func TestModelViewShowsPortAndPIDColumns(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{
					Port:      3000,
					Process:   "node",
					PID:       1001,
					Project:   "sniff",
					Framework: "Node.js",
					Uptime:    "7m 7s",
					Status:    "healthy",
				},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	view := model.View()
	for _, header := range []string{"PORT", "PROCESS", "PID", "PROJECT", "FRAMEWORK", "UPTIME", "STATUS"} {
		if !strings.Contains(view, header) {
			t.Fatalf("expected view to include %q header, got:\n%s", header, view)
		}
	}
	for _, val := range []string{":3000", "1001", "node", "sniff", "Node.js", "7m 7s", "healthy"} {
		if !strings.Contains(view, val) {
			t.Fatalf("expected view to include %q, got:\n%s", val, view)
		}
	}
}

func TestModelViewShowsDetailsForSelectedRow(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{
					Port:       3000,
					Process:    "node",
					PID:        1001,
					Project:    "sniff",
					Framework:  "Node.js",
					Command:    "node server.js",
					Executable: "/usr/bin/node",
					User:       "alice",
				},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)
	view := model.View()
	for _, val := range []string{"Details", "PID: 1001", "Command: node server.js", "Executable: /usr/bin/node", "User: alice"} {
		if !strings.Contains(view, val) {
			t.Fatalf("expected details view to include %q, got:\n%s", val, view)
		}
	}
}

func TestModelViewCompactsDetailsOnNarrowWidth(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{
					Port:       3000,
					Process:    "node",
					PID:        1001,
					Command:    "node server.js",
					Executable: "/usr/bin/node",
					User:       "alice",
				},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	model = updated.(app.Model)

	view := model.View()
	if !strings.Contains(view, "Details (compact)") {
		t.Fatalf("expected compact details mode on narrow width, got:\n%s", view)
	}
}

func TestModelKeepsSelectionByIdentityAcrossRefresh(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{Port: 3000, PID: 1001, Process: "node"},
				{Port: 5173, PID: 2222, Process: "vite"},
			},
			{
				{Port: 3001, PID: 3333, Process: "python"},
				{Port: 5173, PID: 2222, Process: "vite"},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})

	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(app.Model)

	updated, cmd := model.Update(tea.KeyMsg{Runes: []rune{'r'}})
	model = updated.(app.Model)
	refreshMsg := runCmd(t, cmd)
	updated, _ = model.Update(refreshMsg)
	model = updated.(app.Model)

	if model.Cursor() != 1 {
		t.Fatalf("expected cursor to stay on selected PID identity, got %d", model.Cursor())
	}
}

func TestModelRestrictedRowsRemainVisibleAndMarked(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{Port: 3000, PID: 1001, Process: "node", Restricted: false},
				{Port: 5432, PID: 2002, Process: "postgres", Restricted: true, RestrictionReason: "owned by root"},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	view := model.View()
	if !strings.Contains(view, ":3000") || !strings.Contains(view, ":5432") {
		t.Fatalf("expected both unrestricted and restricted rows to be visible, got:\n%s", view)
	}
	if !strings.Contains(view, "locked") {
		t.Fatalf("expected restricted process marker in view, got:\n%s", view)
	}
}

func TestModelGuardedActionExplainsRestriction(t *testing.T) {
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{
				{Port: 5432, PID: 2002, Process: "postgres", Restricted: true, RestrictionReason: "owned by root"},
			},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'s'}})
	model = updated.(app.Model)
	view := model.View()
	if !strings.Contains(view, "action blocked") {
		t.Fatalf("expected blocked action status, got:\n%s", view)
	}
	if !strings.Contains(view, "rerun with elevated privileges") {
		t.Fatalf("expected elevation guidance for restricted action, got:\n%s", view)
	}
}

func TestModelStopRequiresConfirmationAndUsesSelectedTarget(t *testing.T) {
	stopper := &fakeStopper{
		result: action.Result{Success: true},
	}
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001, Process: "node"}},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		Stopper:   stopper,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'s'}})
	model = updated.(app.Model)
	if strings.Contains(model.View(), "graceful stop succeeded") {
		t.Fatalf("should not stop until confirmed")
	}
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'y'}})
	model = updated.(app.Model)

	if len(stopper.targets) != 1 {
		t.Fatalf("expected one graceful stop call, got %d", len(stopper.targets))
	}
	if stopper.targets[0].PID != 1001 || stopper.targets[0].Port != 3000 {
		t.Fatalf("unexpected stop target: %+v", stopper.targets[0])
	}
}

func TestModelStopFlowShowsResultAndRecentHistory(t *testing.T) {
	stopper := &fakeStopper{
		result: action.Result{Success: true},
	}
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001, Process: "node"}},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		Stopper:   stopper,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'s'}})
	model = updated.(app.Model)
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'y'}})
	model = updated.(app.Model)
	view := model.View()
	if !strings.Contains(view, "graceful stop succeeded") {
		t.Fatalf("expected success status in view, got:\n%s", view)
	}
	if !strings.Contains(view, "Recent actions") {
		t.Fatalf("expected recent action section, got:\n%s", view)
	}
	if !strings.Contains(view, "SIGTERM pid=1001 port=3000 success") {
		t.Fatalf("expected recorded action history, got:\n%s", view)
	}
}

func TestModelOffersExplicitForcePathAfterGracefulNeedsForce(t *testing.T) {
	stopper := &fakeStopper{
		result: action.Result{NeedsForce: true},
	}
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001, Process: "node"}},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		Stopper:   stopper,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'s'}})
	model = updated.(app.Model)
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'y'}})
	model = updated.(app.Model)
	view := model.View()
	if !strings.Contains(view, "graceful stop incomplete") {
		t.Fatalf("expected graceful-stop failure status, got:\n%s", view)
	}
	if !strings.Contains(view, "press [f] to force kill") {
		t.Fatalf("expected explicit force path hint, got:\n%s", view)
	}
}

func TestModelForceKillRequiresOwnConfirmation(t *testing.T) {
	stopper := &fakeStopper{
		result: action.Result{NeedsForce: true},
	}
	scanner := &fakeScanner{
		results: [][]discovery.Listener{
			{{Port: 3000, PID: 1001, Process: "node"}},
		},
	}
	model := app.NewModel(app.Config{
		Scanner:   scanner,
		Stopper:   stopper,
		TickEvery: time.Second,
		TickScheduler: func(time.Duration) tea.Cmd {
			return nil
		},
	})
	initMsg := runCmd(t, model.Init())
	updated, _ := model.Update(initMsg)
	model = updated.(app.Model)
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'s'}})
	model = updated.(app.Model)
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'y'}})
	model = updated.(app.Model)

	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'f'}})
	model = updated.(app.Model)
	if len(stopper.forceCalls) != 0 {
		t.Fatalf("expected no force call before confirmation")
	}
	updated, _ = model.Update(tea.KeyMsg{Runes: []rune{'y'}})
	model = updated.(app.Model)
	if len(stopper.forceCalls) != 1 {
		t.Fatalf("expected exactly one force call, got %d", len(stopper.forceCalls))
	}
	view := model.View()
	if !strings.Contains(view, "force kill succeeded") {
		t.Fatalf("expected force result message in view, got:\n%s", view)
	}
	if !strings.Contains(view, "SIGKILL pid=1001 port=3000 success") {
		t.Fatalf("expected force action history entry, got:\n%s", view)
	}
}
