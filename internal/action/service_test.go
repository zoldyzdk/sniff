package action

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

type fakeSignaler struct {
	calls []signalCall
	err   error
}

type signalCall struct {
	pid int
	sig syscall.Signal
}

func (f *fakeSignaler) Signal(pid int, sig syscall.Signal) error {
	f.calls = append(f.calls, signalCall{pid: pid, sig: sig})
	return f.err
}

type fakeReleaseProbe struct {
	released bool
	err      error
	calls    []probeCall
}

type probeCall struct {
	port int
	wait time.Duration
}

func (f *fakeReleaseProbe) WaitUntilReleased(context.Context, int, time.Duration) (bool, error) {
	return f.released, f.err
}

func TestGracefulStop_SignalsAndReportsReleased(t *testing.T) {
	signaler := &fakeSignaler{}
	probe := &fakeReleaseProbe{released: true}
	svc := NewService(ServiceConfig{
		Signaler: signaler,
		Probe:    probe,
		WaitFor:  200 * time.Millisecond,
	})

	result := svc.GracefulStop(context.Background(), Target{PID: 4242, Port: 3000})

	if !result.Success {
		t.Fatalf("expected success, got %+v", result)
	}
	if result.NeedsForce {
		t.Fatalf("expected no force escalation, got %+v", result)
	}
	if len(signaler.calls) != 1 {
		t.Fatalf("expected one signal call, got %d", len(signaler.calls))
	}
	if signaler.calls[0].sig != syscall.SIGTERM {
		t.Fatalf("expected SIGTERM, got %v", signaler.calls[0].sig)
	}
}

func TestGracefulStop_RequestsForcePathWhenPortStillBound(t *testing.T) {
	signaler := &fakeSignaler{}
	probe := &fakeReleaseProbe{released: false}
	svc := NewService(ServiceConfig{
		Signaler: signaler,
		Probe:    probe,
		WaitFor:  200 * time.Millisecond,
	})

	result := svc.GracefulStop(context.Background(), Target{PID: 111, Port: 8080})

	if result.Success {
		t.Fatalf("expected failure result when port remains bound, got %+v", result)
	}
	if !result.NeedsForce {
		t.Fatalf("expected escalation requirement, got %+v", result)
	}
}

func TestGracefulStop_ReturnsSignalError(t *testing.T) {
	signaler := &fakeSignaler{err: errors.New("permission denied")}
	svc := NewService(ServiceConfig{
		Signaler: signaler,
		Probe:    &fakeReleaseProbe{released: true},
	})

	result := svc.GracefulStop(context.Background(), Target{PID: 999, Port: 5000})
	if result.Err == nil {
		t.Fatalf("expected signal error, got %+v", result)
	}
	if result.Err.Error() != "permission denied" {
		t.Fatalf("unexpected error: %v", result.Err)
	}
}
