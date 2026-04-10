package refresh

import (
	"testing"
	"time"

	"github.com/zoldyzdk/sniff/internal/discovery"
)

func TestCoordinatorFlagsQuickRebind(t *testing.T) {
	c := NewCoordinator(2 * time.Second)
	now := time.Unix(1700000000, 0)

	c.MarkTargeted(3000, now)
	ev := c.Observe([]discovery.Listener{{Port: 3000, PID: 1234}}, now.Add(1*time.Second))

	if len(ev.ReboundPorts) != 1 || ev.ReboundPorts[0] != 3000 {
		t.Fatalf("expected quick rebind on 3000, got %+v", ev)
	}
}

func TestCoordinatorIgnoresLateRebind(t *testing.T) {
	c := NewCoordinator(2 * time.Second)
	now := time.Unix(1700000000, 0)

	c.MarkTargeted(3000, now)
	ev := c.Observe([]discovery.Listener{{Port: 3000, PID: 1234}}, now.Add(5*time.Second))
	if len(ev.ReboundPorts) != 0 {
		t.Fatalf("expected no quick rebind outside window, got %+v", ev)
	}
}
