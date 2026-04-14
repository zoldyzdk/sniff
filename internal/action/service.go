package action

import (
	"context"
	"syscall"
	"time"
)

type Signaler interface {
	Signal(pid int, sig syscall.Signal) error
}

type ReleaseProbe interface {
	WaitUntilReleased(ctx context.Context, port int, waitFor time.Duration) (bool, error)
}

type ServiceConfig struct {
	Signaler Signaler
	Probe    ReleaseProbe
	WaitFor  time.Duration
}

type Service struct {
	signaler Signaler
	probe    ReleaseProbe
	waitFor  time.Duration
}

type Target struct {
	PID  int
	Port int
}

type Result struct {
	Success    bool
	NeedsForce bool
	Err        error
}

func NewService(cfg ServiceConfig) Service {
	waitFor := cfg.WaitFor
	if waitFor <= 0 {
		waitFor = 2 * time.Second
	}
	return Service{
		signaler: cfg.Signaler,
		probe:    cfg.Probe,
		waitFor:  waitFor,
	}
}

func (s Service) GracefulStop(ctx context.Context, target Target) Result {
	if s.signaler != nil {
		if err := s.signaler.Signal(target.PID, syscall.SIGTERM); err != nil {
			return Result{Err: err}
		}
	}
	if s.probe == nil {
		return Result{Success: true}
	}
	released, err := s.probe.WaitUntilReleased(ctx, target.Port, s.waitFor)
	if err != nil {
		return Result{Err: err}
	}
	if released {
		return Result{Success: true}
	}
	return Result{NeedsForce: true}
}
