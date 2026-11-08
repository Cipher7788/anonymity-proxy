package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReadinessRecoversAfterTransientFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	probes := 0
	err := waitForReadiness(ctx, time.Millisecond, func(context.Context) error {
		probes++
		if probes < 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil || probes != 3 {
		t.Fatalf("recovery failed: probes=%d error=%v", probes, err)
	}
}

func TestReadinessRetainsLastErrorAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probes := 0
	err := waitForReadiness(ctx, time.Millisecond, func(context.Context) error {
		probes++
		cancel()
		return errors.New("TLS certificate hostname mismatch")
	})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "TLS certificate hostname mismatch") || probes != 1 {
		t.Fatalf("lost readiness cause: probes=%d error=%v", probes, err)
	}
}

func TestReadinessCancelsInFlightProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	probes := 0
	err := waitForReadiness(ctx, time.Millisecond, func(ctx context.Context) error { probes++; <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, context.DeadlineExceeded) || probes != 1 {
		t.Fatalf("probe did not honor deadline: probes=%d error=%v", probes, err)
	}
}

func TestReadinessDoesNotProbeAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := waitForReadiness(ctx, time.Millisecond, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("unexpected probe after cancellation: %v", err)
	}
}
