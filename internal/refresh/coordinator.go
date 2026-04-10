package refresh

import (
	"time"

	"github.com/zoldyzdk/sniff/internal/discovery"
)

type Events struct {
	ReboundPorts []int
}

type Coordinator struct {
	window   time.Duration
	targeted map[int]time.Time
}

func NewCoordinator(window time.Duration) *Coordinator {
	if window <= 0 {
		window = 2 * time.Second
	}
	return &Coordinator{
		window:   window,
		targeted: map[int]time.Time{},
	}
}

func (c *Coordinator) MarkTargeted(port int, now time.Time) {
	c.targeted[port] = now
}

func (c *Coordinator) Observe(listeners []discovery.Listener, now time.Time) Events {
	seen := map[int]struct{}{}
	events := Events{}
	for _, l := range listeners {
		seen[l.Port] = struct{}{}
		targetedAt, ok := c.targeted[l.Port]
		if !ok {
			continue
		}
		if now.Sub(targetedAt) <= c.window {
			events.ReboundPorts = append(events.ReboundPorts, l.Port)
		}
		delete(c.targeted, l.Port)
	}
	for port, targetedAt := range c.targeted {
		if now.Sub(targetedAt) > c.window {
			delete(c.targeted, port)
		}
	}
	return events
}
