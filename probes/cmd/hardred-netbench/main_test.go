package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"vgt-hardred/probes/internal/metrics"
	"vgt-hardred/probes/internal/netbench"
)

func TestComputeLatencyStatsPercentiles(t *testing.T) {
	samples := make([]float64, 100)
	for i := 0; i < 100; i++ {
		samples[i] = float64(100 - i) // unsorted 100..1
	}
	stats := metrics.ComputeLatencyStats(samples)
	if stats.Count != 100 {
		t.Fatalf("expected count 100, got %d", stats.Count)
	}
	if stats.P50Ms != 50 {
		t.Fatalf("expected p50_ms=50, got %v", stats.P50Ms)
	}
	if stats.P95Ms != 95 {
		t.Fatalf("expected p95_ms=95, got %v", stats.P95Ms)
	}
	if stats.P99Ms != 99 {
		t.Fatalf("expected p99_ms=99, got %v", stats.P99Ms)
	}
	if stats.MaxMs != 100 {
		t.Fatalf("expected max_ms=100, got %v", stats.MaxMs)
	}
	if stats.MeanMs != 50.5 {
		t.Fatalf("expected mean_ms=50.5, got %v", stats.MeanMs)
	}

	empty := metrics.ComputeLatencyStats(nil)
	if empty.Count != 0 || empty.MaxMs != 0 {
		t.Fatalf("expected zero stats for empty slice, got %+v", empty)
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := netbench.ParsePorts("22, 80, 443, 8080")
	if err != nil {
		t.Fatalf("ParsePorts failed: %v", err)
	}
	if len(ports) != 4 || ports[0] != 22 || ports[3] != 8080 {
		t.Fatalf("unexpected ports: %v", ports)
	}
	for _, bad := range []string{"", "0", "65536", "80,abc"} {
		if _, err := netbench.ParsePorts(bad); err == nil {
			t.Fatalf("expected ParsePorts(%q) to fail", bad)
		}
	}
}

func TestHTTPBenchAgainstLocalServer(t *testing.T) {
	var seq atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := seq.Add(1)
		switch {
		case n%10 == 0:
			w.WriteHeader(http.StatusInternalServerError)
		case n%5 == 0:
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	res, err := netbench.RunHTTPBench(netbench.HTTPBenchOptions{
		URL:         srv.URL,
		Requests:    40,
		Concurrency: 8,
		TimeoutMs:   2000,
	})
	if err != nil {
		t.Fatalf("RunHTTPBench: %v", err)
	}
	if res.Requests != 40 {
		t.Fatalf("expected 40 requests, got %d", res.Requests)
	}
	if res.OK2xx+res.Blocked4xx+res.Server5xx != 40 || res.TransportErrors != 0 {
		t.Fatalf("unexpected status totals: %+v", res)
	}
	if res.OK2xx != 32 || res.Blocked4xx != 4 || res.Server5xx != 4 {
		t.Fatalf("expected 32/4/4 split, got %+v", res)
	}
	if res.RPS <= 0 || res.P50Ms > res.P95Ms || res.P95Ms > res.P99Ms || res.P99Ms > res.MaxMs {
		t.Fatalf("invalid latency/rps ordering: %+v", res)
	}
}

func TestRateBurstDetectionAndRecovery(t *testing.T) {
	var count atomic.Int64
	var allowRecovery atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowRecovery.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		n := count.Add(1)
		if n > 8 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := netbench.RunRateBurst(netbench.RateBurstOptions{
		URL:            srv.URL,
		Requests:       20,
		Concurrency:    1, // deterministic order so first_block_idx == 8
		TimeoutMs:      2000,
		RecoveryWaitMs: 0,
		RecoveryProbes: 0,
	})
	if err != nil {
		t.Fatalf("RunRateBurst: %v", err)
	}
	if res.OK2xx != 8 || res.RateLimited429 != 12 {
		t.Fatalf("expected 8 ok and 12 429s, got %+v", res)
	}
	if res.FirstBlockIdx != 8 || res.FirstBlockType != "http_429" {
		t.Fatalf("expected first_block_idx=8 (http_429), got idx=%d type=%s", res.FirstBlockIdx, res.FirstBlockType)
	}

	allowRecovery.Store(true)
	resRec, err := netbench.RunRateBurst(netbench.RateBurstOptions{
		URL:            srv.URL,
		Requests:       4,
		Concurrency:    2,
		TimeoutMs:      2000,
		RecoveryWaitMs: 10,
		RecoveryProbes: 3,
	})
	if err != nil {
		t.Fatalf("RunRateBurst recovery: %v", err)
	}
	if !resRec.Recovered || resRec.RecoveryOK != 3 {
		t.Fatalf("expected recovered=true with 3 OK probes, got %+v", resRec)
	}
}

func TestPortScanLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	openPort := ln.Addr().(*net.TCPAddr).Port

	// Allocate and immediately close a port to get a likely-closed port.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	res, err := netbench.RunPortScan(netbench.PortScanOptions{
		Host:      "127.0.0.1",
		Ports:     []int{openPort, closedPort},
		TimeoutMs: 500,
		DelayMs:   0,
	})
	if err != nil {
		t.Fatalf("RunPortScan: %v", err)
	}
	if len(res.OpenPorts) != 1 || res.OpenPorts[0] != openPort {
		t.Fatalf("expected open port %d, got %+v", openPort, res)
	}
}

func TestSSHSprayStopsEarlyAfterConsecutiveDrops(t *testing.T) {
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := closedLn.Addr().String()
	_ = closedLn.Close()

	res, err := netbench.RunSSHSpray(netbench.SSHSprayOptions{
		Addr:      addr,
		Attempts:  18,
		DelayMs:   0,
		TimeoutMs: 500,
	})
	if err != nil {
		t.Fatalf("RunSSHSpray: %v", err)
	}
	if res.FirstDropIdx != 0 || res.TCPRefused != 4 || len(res.Results) != 4 {
		t.Fatalf("expected early stop at 4 consecutive drops, got first=%d refused=%d results=%d", res.FirstDropIdx, res.TCPRefused, len(res.Results))
	}
}

func TestNetbenchCLIHelp(t *testing.T) {
	if code := run([]string{"--help"}); code != 0 {
		t.Fatalf("expected --help to return 0, got %d", code)
	}
	if code := run(nil); code == 0 {
		t.Fatalf("expected empty args to return non-zero")
	}
}
