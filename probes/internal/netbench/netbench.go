// Package netbench implements HTTP, rate-limit, portscan, and SSH auth-spray network benchmarks.
package netbench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"vgt-hardred/probes/internal/metrics"
)

const (
	maxRequests    = 50000
	maxConcurrency = 512
	maxPorts       = 1024
	maxSSHAttempts = 200
)

// HTTPBenchOptions configures http-bench.
type HTTPBenchOptions struct {
	URL         string
	Requests    int
	Concurrency int
	TimeoutMs   int
	Insecure    bool
}

// HTTPBenchResult holds strict JSON summary metrics for http-bench.
type HTTPBenchResult struct {
	Probe           string  `json:"probe"`
	URL             string  `json:"url"`
	Requests        int     `json:"requests"`
	Concurrency     int     `json:"concurrency"`
	OK2xx           int     `json:"ok_2xx"`
	Blocked4xx      int     `json:"blocked_4xx"`
	Server5xx       int     `json:"server_5xx"`
	TransportErrors int     `json:"transport_errors"`
	RPS             float64 `json:"rps"`
	P50Ms           float64 `json:"p50_ms"`
	P95Ms           float64 `json:"p95_ms"`
	P99Ms           float64 `json:"p99_ms"`
	MaxMs           float64 `json:"max_ms"`
	MeanMs          float64 `json:"mean_ms"`
	TotalMs         float64 `json:"total_ms"`
}

// RunHTTPBench executes a concurrent HTTP GET benchmark and returns latency percentiles and status counts.
func RunHTTPBench(opts HTTPBenchOptions) (*HTTPBenchResult, error) {
	if opts.URL == "" {
		return nil, errors.New("url is required")
	}
	if opts.Requests <= 0 || opts.Requests > maxRequests {
		return nil, fmt.Errorf("requests %d out of bounds [1, %d]", opts.Requests, maxRequests)
	}
	if opts.Concurrency <= 0 || opts.Concurrency > maxConcurrency {
		return nil, fmt.Errorf("concurrency %d out of bounds [1, %d]", opts.Concurrency, maxConcurrency)
	}
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 60000 {
		return nil, fmt.Errorf("timeout-ms %d out of bounds [1, 60000]", opts.TimeoutMs)
	}

	client := newHTTPClient(opts.TimeoutMs, opts.Concurrency, opts.Insecure)
	defer client.CloseIdleConnections()

	latencies := make([]float64, opts.Requests)
	statuses := make([]int, opts.Requests)
	var nextIdx atomic.Int64
	var ok2xx, blocked4xx, server5xx, transportErr atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	workers := opts.Concurrency
	if workers > opts.Requests {
		workers = opts.Requests
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				idx := int(nextIdx.Add(1) - 1)
				if idx >= opts.Requests {
					return
				}
				reqStart := time.Now()
				code, err := doGET(client, opts.URL, time.Duration(opts.TimeoutMs)*time.Millisecond)
				latencies[idx] = float64(time.Since(reqStart).Microseconds()) / 1000.0
				statuses[idx] = code
				if err != nil {
					transportErr.Add(1)
					continue
				}
				switch {
				case code >= 200 && code < 300:
					ok2xx.Add(1)
				case code >= 400 && code < 500:
					blocked4xx.Add(1)
				case code >= 500:
					server5xx.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	totalDur := time.Since(start)
	totalMs := float64(totalDur.Microseconds()) / 1000.0
	rps := 0.0
	if totalDur.Seconds() > 0 {
		rps = round3(float64(opts.Requests) / totalDur.Seconds())
	}
	stats := metrics.ComputeLatencyStats(latencies)

	return &HTTPBenchResult{
		Probe:           "http-bench",
		URL:             opts.URL,
		Requests:        opts.Requests,
		Concurrency:     workers,
		OK2xx:           int(ok2xx.Load()),
		Blocked4xx:      int(blocked4xx.Load()),
		Server5xx:       int(server5xx.Load()),
		TransportErrors: int(transportErr.Load()),
		RPS:             rps,
		P50Ms:           stats.P50Ms,
		P95Ms:           stats.P95Ms,
		P99Ms:           stats.P99Ms,
		MaxMs:           stats.MaxMs,
		MeanMs:          stats.MeanMs,
		TotalMs:         round3(totalMs),
	}, nil
}

// RateBurstOptions configures rate-burst.
type RateBurstOptions struct {
	URL            string
	Requests       int
	Concurrency    int
	TimeoutMs      int
	RecoveryWaitMs int
	RecoveryProbes int
	Insecure       bool
}

// RateBurstResult reports rate-limit tripping threshold and post-pause recovery.
type RateBurstResult struct {
	Probe           string  `json:"probe"`
	URL             string  `json:"url"`
	Requests        int     `json:"requests"`
	Concurrency     int     `json:"concurrency"`
	OK2xx           int     `json:"ok_2xx"`
	RateLimited429  int     `json:"rate_limited_429"`
	Blocked403      int     `json:"blocked_403"`
	Other4xx        int     `json:"other_4xx"`
	Server5xx       int     `json:"server_5xx"`
	Timeouts        int     `json:"timeouts"`
	TransportErrors int     `json:"transport_errors"`
	FirstBlockIdx   int     `json:"first_block_idx"`
	FirstBlockType  string  `json:"first_block_type,omitempty"`
	P50Ms           float64 `json:"p50_ms"`
	P95Ms           float64 `json:"p95_ms"`
	MaxMs           float64 `json:"max_ms"`
	RecoveryWaitMs  int     `json:"recovery_wait_ms"`
	RecoveryProbes  int     `json:"recovery_probes"`
	RecoveryOK      int     `json:"recovery_ok"`
	RecoveryBlocked int     `json:"recovery_blocked"`
	RecoveryErrors  int     `json:"recovery_errors"`
	Recovered       bool    `json:"recovered"`
}

// RunRateBurst fires a burst of requests to locate the rate-limit threshold and tests recovery after a pause.
func RunRateBurst(opts RateBurstOptions) (*RateBurstResult, error) {
	if opts.URL == "" {
		return nil, errors.New("url is required")
	}
	if opts.Requests <= 0 || opts.Requests > maxRequests {
		return nil, fmt.Errorf("requests %d out of bounds [1, %d]", opts.Requests, maxRequests)
	}
	if opts.Concurrency <= 0 || opts.Concurrency > maxConcurrency {
		return nil, fmt.Errorf("concurrency %d out of bounds [1, %d]", opts.Concurrency, maxConcurrency)
	}
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 60000 {
		return nil, fmt.Errorf("timeout-ms %d out of bounds [1, 60000]", opts.TimeoutMs)
	}
	if opts.RecoveryWaitMs < 0 || opts.RecoveryWaitMs > 60000 {
		return nil, fmt.Errorf("recovery-wait-ms %d out of bounds [0, 60000]", opts.RecoveryWaitMs)
	}
	if opts.RecoveryProbes < 0 || opts.RecoveryProbes > 100 {
		return nil, fmt.Errorf("recovery-probes %d out of bounds [0, 100]", opts.RecoveryProbes)
	}

	client := newHTTPClient(opts.TimeoutMs, opts.Concurrency, opts.Insecure)
	defer client.CloseIdleConnections()

	type burstSample struct {
		status  int
		timeout bool
		err     bool
		ms      float64
	}
	samples := make([]burstSample, opts.Requests)
	var nextIdx atomic.Int64
	var wg sync.WaitGroup

	workers := opts.Concurrency
	if workers > opts.Requests {
		workers = opts.Requests
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				idx := int(nextIdx.Add(1) - 1)
				if idx >= opts.Requests {
					return
				}
				reqStart := time.Now()
				code, err := doGET(client, opts.URL, time.Duration(opts.TimeoutMs)*time.Millisecond)
				s := burstSample{
					status: code,
					ms:     float64(time.Since(reqStart).Microseconds()) / 1000.0,
				}
				if err != nil {
					s.err = true
					s.timeout = isTimeoutError(err)
				}
				samples[idx] = s
			}
		}()
	}
	wg.Wait()

	res := &RateBurstResult{
		Probe:          "rate-burst",
		URL:            opts.URL,
		Requests:       opts.Requests,
		Concurrency:    workers,
		FirstBlockIdx:  -1,
		RecoveryWaitMs: opts.RecoveryWaitMs,
		RecoveryProbes: opts.RecoveryProbes,
	}

	latencies := make([]float64, len(samples))
	for i, s := range samples {
		latencies[i] = s.ms
		if s.err {
			if s.timeout {
				res.Timeouts++
				if res.FirstBlockIdx == -1 {
					res.FirstBlockIdx = i
					res.FirstBlockType = "timeout"
				}
			} else {
				res.TransportErrors++
				if res.FirstBlockIdx == -1 {
					res.FirstBlockIdx = i
					res.FirstBlockType = "transport_error"
				}
			}
			continue
		}
		switch {
		case s.status >= 200 && s.status < 300:
			res.OK2xx++
		case s.status == http.StatusTooManyRequests:
			res.RateLimited429++
			if res.FirstBlockIdx == -1 {
				res.FirstBlockIdx = i
				res.FirstBlockType = "http_429"
			}
		case s.status == http.StatusForbidden:
			res.Blocked403++
			if res.FirstBlockIdx == -1 {
				res.FirstBlockIdx = i
				res.FirstBlockType = "http_403"
			}
		case s.status >= 400 && s.status < 500:
			res.Other4xx++
		case s.status >= 500:
			res.Server5xx++
		}
	}

	stats := metrics.ComputeLatencyStats(latencies)
	res.P50Ms = stats.P50Ms
	res.P95Ms = stats.P95Ms
	res.MaxMs = stats.MaxMs

	if opts.RecoveryProbes > 0 {
		if opts.RecoveryWaitMs > 0 {
			time.Sleep(time.Duration(opts.RecoveryWaitMs) * time.Millisecond)
		}
		for p := 0; p < opts.RecoveryProbes; p++ {
			code, err := doGET(client, opts.URL, time.Duration(opts.TimeoutMs)*time.Millisecond)
			if err != nil {
				res.RecoveryErrors++
				continue
			}
			if code >= 200 && code < 300 {
				res.RecoveryOK++
			} else if code == http.StatusTooManyRequests || code == http.StatusForbidden {
				res.RecoveryBlocked++
			}
		}
		res.Recovered = res.RecoveryOK == opts.RecoveryProbes
	}

	return res, nil
}

// PortScanOptions configures portscan.
type PortScanOptions struct {
	Host      string
	Ports     []int
	TimeoutMs int
	DelayMs   int
}

// PortOutcome records one TCP connect scan probe.
type PortOutcome struct {
	Idx       int     `json:"idx"`
	Port      int     `json:"port"`
	State     string  `json:"state"`
	Error     string  `json:"error,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// PortScanResult summarizes TCP port scan progression and mid-scan XDP/firewall drops.
type PortScanResult struct {
	Probe                   string        `json:"probe"`
	Host                    string        `json:"host"`
	TotalPorts              int           `json:"total_ports"`
	OpenPorts               []int         `json:"open_ports"`
	ClosedPorts             []int         `json:"closed_ports"`
	TimeoutPorts            []int         `json:"timeout_ports"`
	ErrorPorts              []int         `json:"error_ports"`
	FirstTimeoutIdx         int           `json:"first_timeout_idx"`
	FirstTimeoutPort        int           `json:"first_timeout_port"`
	TailConsecutiveTimeouts int           `json:"tail_consecutive_timeouts"`
	Results                 []PortOutcome `json:"results"`
	TotalElapsedMs          float64       `json:"total_elapsed_ms"`
}

// ParsePorts parses a comma-separated port list with strict [1, 65535] validation.
func ParsePorts(spec string) ([]int, error) {
	parts := strings.Split(spec, ",")
	if len(parts) == 0 || (len(parts) == 1 && strings.TrimSpace(parts[0]) == "") {
		return nil, errors.New("ports list is empty")
	}
	if len(parts) > maxPorts {
		return nil, fmt.Errorf("too many ports (%d > %d)", len(parts), maxPorts)
	}
	ports := make([]int, 0, len(parts))
	for _, raw := range parts {
		p, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// RunPortScan probes each port sequentially to measure connect responses and detect mid-scan host drops.
func RunPortScan(opts PortScanOptions) (*PortScanResult, error) {
	if strings.TrimSpace(opts.Host) == "" {
		return nil, errors.New("host is required")
	}
	if len(opts.Ports) == 0 || len(opts.Ports) > maxPorts {
		return nil, fmt.Errorf("port count %d out of bounds [1, %d]", len(opts.Ports), maxPorts)
	}
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 30000 {
		return nil, fmt.Errorf("timeout-ms %d out of bounds [1, 30000]", opts.TimeoutMs)
	}
	if opts.DelayMs < 0 || opts.DelayMs > 5000 {
		return nil, fmt.Errorf("delay-ms %d out of bounds [0, 5000]", opts.DelayMs)
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	start := time.Now()
	res := &PortScanResult{
		Probe:            "portscan",
		Host:             opts.Host,
		TotalPorts:       len(opts.Ports),
		OpenPorts:        []int{},
		ClosedPorts:      []int{},
		TimeoutPorts:     []int{},
		ErrorPorts:       []int{},
		FirstTimeoutIdx:  -1,
		FirstTimeoutPort: -1,
		Results:          make([]PortOutcome, 0, len(opts.Ports)),
	}

	for i, port := range opts.Ports {
		pStart := time.Now()
		addr := net.JoinHostPort(opts.Host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := float64(time.Since(pStart).Microseconds()) / 1000.0
		po := PortOutcome{Idx: i, Port: port, ElapsedMs: round3(elapsed)}
		if err == nil {
			_ = conn.Close()
			po.State = "open"
			res.OpenPorts = append(res.OpenPorts, port)
			res.TailConsecutiveTimeouts = 0
		} else if isTimeoutError(err) {
			po.State = "timeout"
			po.Error = err.Error()
			res.TimeoutPorts = append(res.TimeoutPorts, port)
			if res.FirstTimeoutIdx == -1 {
				res.FirstTimeoutIdx = i
				res.FirstTimeoutPort = port
			}
			res.TailConsecutiveTimeouts++
		} else if isRefusedError(err) {
			po.State = "closed"
			po.Error = err.Error()
			res.ClosedPorts = append(res.ClosedPorts, port)
			res.TailConsecutiveTimeouts = 0
		} else {
			po.State = "error"
			po.Error = err.Error()
			res.ErrorPorts = append(res.ErrorPorts, port)
		}
		res.Results = append(res.Results, po)

		if opts.DelayMs > 0 && i+1 < len(opts.Ports) {
			time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
		}
	}

	res.TotalElapsedMs = round3(float64(time.Since(start).Microseconds()) / 1000.0)
	return res, nil
}

// SSHSprayOptions configures ssh-spray.
type SSHSprayOptions struct {
	Addr       string
	Attempts   int
	DelayMs    int
	TimeoutMs  int
	UserPrefix string
}

// SSHAttemptOutcome records one invalid-user SSH auth attempt.
type SSHAttemptOutcome struct {
	Idx       int     `json:"idx"`
	Username  string  `json:"username"`
	Outcome   string  `json:"outcome"`
	Error     string  `json:"error,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// SSHSprayResult summarizes bounded invalid-user SSH auth attempts.
type SSHSprayResult struct {
	Probe          string              `json:"probe"`
	Addr           string              `json:"addr"`
	Attempts       int                 `json:"attempts"`
	AuthFailed     int                 `json:"auth_failed"`
	Timeouts       int                 `json:"timeouts"`
	TCPRefused     int                 `json:"tcp_refused"`
	OtherErrors    int                 `json:"other_errors"`
	FirstDropIdx   int                 `json:"first_drop_idx"`
	Results        []SSHAttemptOutcome `json:"results"`
	TotalElapsedMs float64             `json:"total_elapsed_ms"`
}

// RunSSHSpray performs bounded invalid-user SSH authentication attempts to exercise sshd/CrowdSec detection.
func RunSSHSpray(opts SSHSprayOptions) (*SSHSprayResult, error) {
	if strings.TrimSpace(opts.Addr) == "" {
		return nil, errors.New("addr is required")
	}
	if opts.Attempts <= 0 || opts.Attempts > maxSSHAttempts {
		return nil, fmt.Errorf("attempts %d out of bounds [1, %d]", opts.Attempts, maxSSHAttempts)
	}
	if opts.DelayMs < 0 || opts.DelayMs > 10000 {
		return nil, fmt.Errorf("delay-ms %d out of bounds [0, 10000]", opts.DelayMs)
	}
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 30000 {
		return nil, fmt.Errorf("timeout-ms %d out of bounds [1, 30000]", opts.TimeoutMs)
	}
	prefix := opts.UserPrefix
	if prefix == "" {
		prefix = "hardred_invalid_"
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	start := time.Now()
	res := &SSHSprayResult{
		Probe:        "ssh-spray",
		Addr:         opts.Addr,
		Attempts:     opts.Attempts,
		FirstDropIdx: -1,
		Results:      make([]SSHAttemptOutcome, 0, opts.Attempts),
	}

	_, privKey, kErr := ed25519.GenerateKey(rand.Reader)
	var authMethods []ssh.AuthMethod
	if kErr == nil {
		if signer, sErr := ssh.NewSignerFromKey(privKey); sErr == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}
	authMethods = append(authMethods, ssh.Password("HardRedInvalidPass!2026"))

	consecutiveDrops := 0
	for i := 0; i < opts.Attempts; i++ {
		user := fmt.Sprintf("%s%02d", prefix, i)
		aStart := time.Now()
		rawConn, dErr := net.DialTimeout("tcp", opts.Addr, timeout)
		var client *ssh.Client
		var err error
		if dErr != nil {
			err = dErr
		} else {
			_ = rawConn.SetDeadline(time.Now().Add(timeout))
			cfg := &ssh.ClientConfig{
				User:            user,
				Auth:            authMethods,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         timeout,
			}
			c, chans, reqs, hErr := ssh.NewClientConn(rawConn, opts.Addr, cfg)
			if hErr != nil {
				_ = rawConn.Close()
				err = hErr
			} else {
				client = ssh.NewClient(c, chans, reqs)
			}
		}
		elapsed := round3(float64(time.Since(aStart).Microseconds()) / 1000.0)
		ao := SSHAttemptOutcome{
			Idx:       i,
			Username:  user,
			ElapsedMs: elapsed,
		}
		if err == nil {
			_ = client.Close()
			ao.Outcome = "unexpected_auth_success"
			consecutiveDrops = 0
		} else {
			errMsg := err.Error()
			ao.Error = errMsg
			switch {
			case strings.Contains(errMsg, "unable to authenticate"):
				ao.Outcome = "auth_failed"
				res.AuthFailed++
				consecutiveDrops = 0
			case isTimeoutError(err):
				ao.Outcome = "timeout"
				res.Timeouts++
				consecutiveDrops++
				if res.FirstDropIdx == -1 {
					res.FirstDropIdx = i
				}
			case isRefusedError(err):
				ao.Outcome = "tcp_refused"
				res.TCPRefused++
				consecutiveDrops++
				if res.FirstDropIdx == -1 {
					res.FirstDropIdx = i
				}
			default:
				ao.Outcome = "other_error"
				res.OtherErrors++
				// Treat dropped/reset SSH handshakes before auth as dropped connectivity too.
				low := strings.ToLower(errMsg)
				if strings.Contains(low, "eof") || strings.Contains(low, "reset") || strings.Contains(low, "handshake") {
					consecutiveDrops++
					if res.FirstDropIdx == -1 {
						res.FirstDropIdx = i
					}
				} else {
					consecutiveDrops = 0
				}
			}
		}
		res.Results = append(res.Results, ao)

		// Stop early once sustained packet/TCP drops prove an active ban (saves N * TimeoutMs).
		if consecutiveDrops >= 4 {
			break
		}

		if opts.DelayMs > 0 && i+1 < opts.Attempts {
			time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
		}
	}

	res.TotalElapsedMs = round3(float64(time.Since(start).Microseconds()) / 1000.0)
	return res, nil
}

func newHTTPClient(timeoutMs, concurrency int, insecure bool) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency * 2,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec // Explicitly requested for self-signed test targets.
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
	}
}

func doGET(client *http.Client, targetURL string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func isRefusedError(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") || strings.Contains(msg, "verweigerte")
}

func round3(v float64) float64 {
	return float64(int(v*1000+0.5)) / 1000
}
