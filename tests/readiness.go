package tests

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// No testing.T is captured here: only the calling subtest decides whether to fail.
// The same context bounds both retries and an in-flight health probe.
func waitForReadiness(ctx context.Context, interval time.Duration, probe func(context.Context) error) error {
	if interval <= 0 {
		return fmt.Errorf("readiness retry interval must be positive")
	}
	started := time.Now()
	attempts := 0
	var last error
	failure := func() error {
		return fmt.Errorf("proxy readiness failed after %d probes (%s); last probe: %v; deadline/cancellation: %w", attempts, time.Since(started).Round(time.Millisecond), last, ctx.Err())
	}
	for {
		if ctx.Err() != nil {
			return failure()
		}
		attempts++
		last = probe(ctx)
		if last == nil {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failure()
		case <-timer.C:
		}
	}
}

// Do not inspect Config.Env or print secret files. These commands show only
// state, port bindings, app startup logs and the container's own health result.
func readinessDiagnostics(root string) string {
	base := []string{"compose", "-f", "compose.yaml", "-f", "compose.runtime.yaml"}
	commands := [][]string{
		{"ps", "-a"},
		{"port", "proxy", "8080"},
		{"exec", "-T", "proxy", "/usr/local/bin/proxy", "-config", "/etc/proxy/config.json", "-healthcheck"},
		{"logs", "--no-color", "--tail", "30", "proxy"},
	}
	var out strings.Builder
	for _, args := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "docker", append(append([]string{}, base...), args...)...)
		cmd.Dir = root
		b, err := cmd.CombinedOutput()
		cancel()
		if len(b) > 16384 {
			b = b[:16384]
		}
		fmt.Fprintf(&out, "docker compose %s: %v\n%s\n", strings.Join(args, " "), err, b)
	}
	return out.String()
}
