package ops

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type LoadOptions struct {
	Target       string
	Duration     time.Duration
	Concurrency  int
	MaxErrorRate float64
	P95Limit     time.Duration
}
type LoadReport struct {
	Completed         uint64  `json:"completed"`
	Errors            uint64  `json:"errors"`
	ErrorRate         float64 `json:"error_rate"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	P50Milliseconds   int     `json:"p50_ms"`
	P95Milliseconds   int     `json:"p95_ms"`
	P99Milliseconds   int     `json:"p99_ms"`
	ElapsedSeconds    float64 `json:"elapsed_seconds"`
	Passed            bool    `json:"passed"`
}

func Load(ctx context.Context, c *http.Client, o LoadOptions) (LoadReport, error) {
	var report LoadReport
	u, e := url.Parse(o.Target)
	if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return report, errors.New("invalid load target")
	}
	if o.Duration < time.Second || o.Duration > time.Hour || o.Concurrency < 1 || o.Concurrency > 1024 || o.MaxErrorRate < 0 || o.MaxErrorRate > 1 || o.P95Limit <= 0 {
		return report, errors.New("invalid load limits")
	}
	ctx, cancel := context.WithTimeout(ctx, o.Duration)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var buckets [60001]uint64
	start := time.Now()
	for i := 0; i < o.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, e := http.NewRequestWithContext(ctx, "GET", o.Target, nil)
				if e != nil {
					return
				}
				before := time.Now()
				resp, e := c.Do(req)
				failed := e != nil
				if e == nil {
					n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20+1))
					resp.Body.Close()
					failed = resp.StatusCode < 200 || resp.StatusCode >= 300 || copyErr != nil || n > 16<<20
				}
				if ctx.Err() != nil {
					return
				} // Do not score work cancelled at the scheduled end.
				ms := int(time.Since(before).Milliseconds())
				if ms > 60000 {
					ms = 60000
				}
				mu.Lock()
				report.Completed++
				if failed {
					report.Errors++
				}
				buckets[ms]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	report.ElapsedSeconds = time.Since(start).Seconds()
	report.RequestsPerSecond = float64(report.Completed) / report.ElapsedSeconds
	if report.Completed > 0 {
		report.ErrorRate = float64(report.Errors) / float64(report.Completed)
	} else {
		report.ErrorRate = 1
	}
	percentile := func(q float64) int {
		threshold := uint64(math.Ceil(float64(report.Completed) * q))
		var n uint64
		for ms, count := range buckets {
			n += count
			if n >= threshold {
				return ms
			}
		}
		return 60000
	}
	report.P50Milliseconds = percentile(.50)
	report.P95Milliseconds = percentile(.95)
	report.P99Milliseconds = percentile(.99)
	report.Passed = report.Completed > 0 && report.ErrorRate <= o.MaxErrorRate && time.Duration(report.P95Milliseconds)*time.Millisecond <= o.P95Limit
	if !report.Passed {
		return report, errors.New("load acceptance thresholds failed")
	}
	return report, nil
}
