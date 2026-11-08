package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func blockUntilCanceled(stopped chan<- struct{}) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}
}

func runWithTimeout(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the manager stopped")
		return nil
	}
}

func TestRunStopsWorkersWhenManagerReturnsCleanly(t *testing.T) {
	discoveryStopped := make(chan struct{})
	providerStopped := make(chan struct{})

	err := runWithTimeout(t, func() error {
		return runUntilManagerStops(context.Background(),
			func(context.Context) error { return nil },
			blockUntilCanceled(discoveryStopped),
			blockUntilCanceled(providerStopped),
		)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for name, ch := range map[string]chan struct{}{"discovery": discoveryStopped, "provider": providerStopped} {
		select {
		case <-ch:
		default:
			t.Errorf("%s was still running after the manager returned", name)
		}
	}
}

func TestRunReturnsManagerError(t *testing.T) {
	workerStopped := make(chan struct{})
	lost := errors.New("leader election lost")

	err := runWithTimeout(t, func() error {
		return runUntilManagerStops(context.Background(),
			func(context.Context) error { return lost },
			blockUntilCanceled(workerStopped),
		)
	})
	if !errors.Is(err, lost) {
		t.Fatalf("got %v, want %v", err, lost)
	}
}

func TestRunStopsManagerWhenWorkerFails(t *testing.T) {
	managerStopped := make(chan struct{})
	failed := errors.New("discovery failed")

	err := runWithTimeout(t, func() error {
		return runUntilManagerStops(context.Background(),
			blockUntilCanceled(managerStopped),
			func(context.Context) error { return failed },
		)
	})
	if !errors.Is(err, failed) {
		t.Fatalf("got %v, want %v", err, failed)
	}
	select {
	case <-managerStopped:
	default:
		t.Error("manager was not stopped after a worker failed")
	}
}

func TestRunStopsEverythingOnSignal(t *testing.T) {
	managerStopped := make(chan struct{})
	workerStopped := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runWithTimeout(t, func() error {
		return runUntilManagerStops(ctx, blockUntilCanceled(managerStopped), blockUntilCanceled(workerStopped))
	})
	if err != nil {
		t.Fatalf("a shutdown signal should not be reported as an error: %v", err)
	}
	<-managerStopped
	<-workerStopped
}
