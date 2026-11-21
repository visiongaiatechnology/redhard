// Package probe implements host-side security and resilience benchmark probes.
package probe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vgt-hardred/probes/internal/jail"
	"vgt-hardred/probes/internal/metrics"
)

const (
	maxRansomCount = 10000
	maxStormCount  = 50000
	maxDelayMs     = 10000
)

// ExecOutcome captures the result of an execution or syscall probe.
type ExecOutcome struct {
	Probe     string  `json:"probe"`
	Target    string  `json:"target,omitempty"`
	OK        bool    `json:"ok"`
	Errno     string  `json:"errno,omitempty"`
	ExitCode  int     `json:"exit_code"`
	Stdout    string  `json:"stdout,omitempty"`
	Error     string  `json:"error,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// AESProgressEntry is one crash-safe JSONL line emitted by aes-ransom.
type AESProgressEntry struct {
	Idx           int     `json:"idx"`
	File          string  `json:"file"`
	EntropyBefore float64 `json:"entropy_before"`
	EntropyAfter  float64 `json:"entropy_after"`
	ElapsedMs     float64 `json:"elapsed_ms"`
}

// AESRansomOptions configures the aes-ransom probe.
type AESRansomOptions struct {
	Sandbox  string
	Count    int
	DelayMs  int
	Progress string
	Jail     *jail.Jail
}

// AESRansomResult summarizes an aes-ransom execution.
type AESRansomResult struct {
	Probe            string  `json:"probe"`
	Sandbox          string  `json:"sandbox"`
	RequestedCount   int     `json:"requested_count"`
	CompletedCount   int     `json:"completed_count"`
	MeanEntropyPre   float64 `json:"mean_entropy_before"`
	MeanEntropyPost  float64 `json:"mean_entropy_after"`
	ProgressFile     string  `json:"progress_file,omitempty"`
	TotalElapsedMs   float64 `json:"total_elapsed_ms"`
}

// RunAESRansom creates realistic 4KB text files inside a jailed sandbox,
// encrypts each with AES-256-GCM, deletes the plaintext original, and syncs progress.
func RunAESRansom(opts AESRansomOptions) (*AESRansomResult, error) {
	j := opts.Jail
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(opts.Sandbox)
	if err != nil {
		return nil, err
	}
	if opts.Count <= 0 || opts.Count > maxRansomCount {
		return nil, fmt.Errorf("count %d out of allowed bounds [1, %d]", opts.Count, maxRansomCount)
	}
	if opts.DelayMs < 0 || opts.DelayMs > maxDelayMs {
		return nil, fmt.Errorf("delay-ms %d out of allowed bounds [0, %d]", opts.DelayMs, maxDelayMs)
	}
	if err := validateProgressPath(opts.Progress, j); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}

	pw, err := metrics.NewSyncJSONLWriter(opts.Progress)
	if err != nil {
		return nil, fmt.Errorf("open progress file: %w", err)
	}
	defer pw.Close()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	var sumPre, sumPost float64
	completed := 0

	for i := 0; i < opts.Count; i++ {
		fileStart := time.Now()
		plainName := fmt.Sprintf("doc_%05d.txt", i)
		plainPath, err := jail.SafeChildPath(sandboxDir, plainName)
		if err != nil {
			return nil, err
		}
		lockedPath, err := jail.SafeChildPath(sandboxDir, plainName+".locked")
		if err != nil {
			return nil, err
		}

		plaintext := buildRealisticTextPayload(i, 4096)
		if err := os.WriteFile(plainPath, plaintext, 0o644); err != nil {
			return nil, fmt.Errorf("write plaintext %s: %w", plainPath, err)
		}

		entBefore := metrics.ShannonEntropy(plaintext)
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
		entAfter := metrics.ShannonEntropy(ciphertext)

		if err := os.WriteFile(lockedPath, ciphertext, 0o644); err != nil {
			return nil, fmt.Errorf("write locked %s: %w", lockedPath, err)
		}
		if err := os.Remove(plainPath); err != nil {
			return nil, fmt.Errorf("remove plaintext %s: %w", plainPath, err)
		}

		entry := AESProgressEntry{
			Idx:           i,
			File:          lockedPath,
			EntropyBefore: entBefore,
			EntropyAfter:  entAfter,
			ElapsedMs:     elapsedMs(fileStart),
		}
		if err := pw.WriteRecord(entry); err != nil {
			return nil, fmt.Errorf("write progress: %w", err)
		}

		sumPre += entBefore
		sumPost += entAfter
		completed++

		if opts.DelayMs > 0 && i+1 < opts.Count {
			time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
		}
	}

	return &AESRansomResult{
		Probe:           "aes-ransom",
		Sandbox:         sandboxDir,
		RequestedCount:  opts.Count,
		CompletedCount:  completed,
		MeanEntropyPre:  round4(sumPre / float64(completed)),
		MeanEntropyPost: round4(sumPost / float64(completed)),
		ProgressFile:    opts.Progress,
		TotalElapsedMs:  elapsedMs(start),
	}, nil
}

// StormBatchEntry is one synced JSONL line emitted by rename-storm.
type StormBatchEntry struct {
	Batch      int     `json:"batch"`
	BatchFiles int     `json:"batch_files"`
	Completed  int     `json:"completed"`
	ElapsedMs  float64 `json:"elapsed_ms"`
}

// RenameStormOptions configures the rename-storm probe.
type RenameStormOptions struct {
	Sandbox  string
	Count    int
	Batch    int
	DelayMs  int
	Progress string
	Jail     *jail.Jail
}

// RenameStormResult summarizes a rename-storm execution.
type RenameStormResult struct {
	Probe          string  `json:"probe"`
	Sandbox        string  `json:"sandbox"`
	RequestedCount int     `json:"requested_count"`
	CompletedCount int     `json:"completed_count"`
	Batches        int     `json:"batches"`
	ProgressFile   string  `json:"progress_file,omitempty"`
	TotalElapsedMs float64 `json:"total_elapsed_ms"`
}

// RunRenameStorm performs rapid batched file write + rename operations inside a jailed sandbox.
func RunRenameStorm(opts RenameStormOptions) (*RenameStormResult, error) {
	j := opts.Jail
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(opts.Sandbox)
	if err != nil {
		return nil, err
	}
	if opts.Count <= 0 || opts.Count > maxStormCount {
		return nil, fmt.Errorf("count %d out of allowed bounds [1, %d]", opts.Count, maxStormCount)
	}
	if opts.Batch <= 0 || opts.Batch > opts.Count {
		return nil, fmt.Errorf("batch %d out of allowed bounds [1, %d]", opts.Batch, opts.Count)
	}
	if opts.DelayMs < 0 || opts.DelayMs > maxDelayMs {
		return nil, fmt.Errorf("delay-ms %d out of allowed bounds [0, %d]", opts.DelayMs, maxDelayMs)
	}
	if err := validateProgressPath(opts.Progress, j); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}

	pw, err := metrics.NewSyncJSONLWriter(opts.Progress)
	if err != nil {
		return nil, fmt.Errorf("open progress file: %w", err)
	}
	defer pw.Close()

	start := time.Now()
	completed := 0
	batches := 0
	payload := []byte("VGT HardRed rename-storm harmless test marker payload\n")

	for completed < opts.Count {
		batchStart := time.Now()
		batchTarget := opts.Batch
		if remaining := opts.Count - completed; remaining < batchTarget {
			batchTarget = remaining
		}
		for k := 0; k < batchTarget; k++ {
			idx := completed + k
			srcPath, err := jail.SafeChildPath(sandboxDir, fmt.Sprintf("storm_%06d.tmp", idx))
			if err != nil {
				return nil, err
			}
			dstPath, err := jail.SafeChildPath(sandboxDir, fmt.Sprintf("storm_%06d.ren", idx))
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
				return nil, fmt.Errorf("write %s: %w", srcPath, err)
			}
			if err := os.Rename(srcPath, dstPath); err != nil {
				return nil, fmt.Errorf("rename %s -> %s: %w", srcPath, dstPath, err)
			}
		}
		completed += batchTarget
		batches++
		if err := pw.WriteRecord(StormBatchEntry{
			Batch:      batches,
			BatchFiles: batchTarget,
			Completed:  completed,
			ElapsedMs:  elapsedMs(batchStart),
		}); err != nil {
			return nil, fmt.Errorf("write progress: %w", err)
		}
		if opts.DelayMs > 0 && completed < opts.Count {
			time.Sleep(time.Duration(opts.DelayMs) * time.Millisecond)
		}
	}

	return &RenameStormResult{
		Probe:          "rename-storm",
		Sandbox:        sandboxDir,
		RequestedCount: opts.Count,
		CompletedCount: completed,
		Batches:        batches,
		ProgressFile:   opts.Progress,
		TotalElapsedMs: elapsedMs(start),
	}, nil
}

// ChildKillOptions configures child-kill-test.
type ChildKillOptions struct {
	Sandbox  string
	Count    int
	DelayMs  int
	Progress string
	Jail     *jail.Jail
}

// ChildStatus describes the termination state of a child process.
type ChildStatus struct {
	Exited   bool   `json:"exited"`
	ExitCode int    `json:"exit_code"`
	Signaled bool   `json:"signaled"`
	Signal   string `json:"signal,omitempty"`
	Stopped  bool   `json:"stopped"`
	Summary  string `json:"summary"`
}

// ChildKillResult summarizes a child-kill-test run.
type ChildKillResult struct {
	Probe          string      `json:"probe"`
	Sandbox        string      `json:"sandbox"`
	ChildPID       int         `json:"child_pid"`
	Status         ChildStatus `json:"status"`
	FilesDamaged   int         `json:"files_damaged"`
	ProgressFile   string      `json:"progress_file,omitempty"`
	TotalElapsedMs float64     `json:"total_elapsed_ms"`
}

// RunChildKillTest spawns a child aes-ransom process and reports its exact exit/signal status
// along with the resulting damaged (.locked) file count inside the sandbox.
func RunChildKillTest(opts ChildKillOptions) (*ChildKillResult, error) {
	j := opts.Jail
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(opts.Sandbox)
	if err != nil {
		return nil, err
	}
	if opts.Count <= 0 || opts.Count > maxRansomCount {
		return nil, fmt.Errorf("count %d out of allowed bounds [1, %d]", opts.Count, maxRansomCount)
	}
	if opts.DelayMs < 0 || opts.DelayMs > maxDelayMs {
		return nil, fmt.Errorf("delay-ms %d out of allowed bounds [0, %d]", opts.DelayMs, maxDelayMs)
	}
	if err := validateProgressPath(opts.Progress, j); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}

	args := []string{
		"aes-ransom",
		"-sandbox", sandboxDir,
		"-count", fmt.Sprintf("%d", opts.Count),
		"-delay-ms", fmt.Sprintf("%d", opts.DelayMs),
	}
	if opts.Progress != "" {
		args = append(args, "-progress", opts.Progress)
	}

	start := time.Now()
	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start child: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()

	status := InspectWaitStatus(cmd.ProcessState)
	damaged := countLockedFiles(sandboxDir)

	return &ChildKillResult{
		Probe:          "child-kill-test",
		Sandbox:        sandboxDir,
		ChildPID:       pid,
		Status:         status,
		FilesDamaged:   damaged,
		ProgressFile:   opts.Progress,
		TotalElapsedMs: elapsedMs(start),
	}, nil
}

// EgressProbeOptions configures egress-probe.
type EgressProbeOptions struct {
	Target    string
	Addr      string
	TimeoutMs int
}

// HTTPEgressOutcome describes an HTTP egress attempt.
type HTTPEgressOutcome struct {
	Target     string  `json:"target"`
	OK         bool    `json:"ok"`
	StatusCode int     `json:"status_code"`
	Error      string  `json:"error,omitempty"`
	Errno      string  `json:"errno,omitempty"`
	ElapsedMs  float64 `json:"elapsed_ms"`
}

// TCPEgressOutcome describes a TCP connect egress attempt.
type TCPEgressOutcome struct {
	Addr      string  `json:"addr"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
	Errno     string  `json:"errno,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// EgressProbeResult summarizes HTTP and TCP egress probes.
type EgressProbeResult struct {
	Probe string             `json:"probe"`
	HTTP  *HTTPEgressOutcome `json:"http,omitempty"`
	TCP   *TCPEgressOutcome  `json:"tcp,omitempty"`
}

// RunEgressProbe tests outbound HTTP and TCP connectivity within timeout-ms.
func RunEgressProbe(opts EgressProbeOptions) (*EgressProbeResult, error) {
	if opts.TimeoutMs <= 0 || opts.TimeoutMs > 60000 {
		return nil, fmt.Errorf("timeout-ms %d out of bounds [1, 60000]", opts.TimeoutMs)
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	res := &EgressProbeResult{Probe: "egress-probe"}

	if opts.Target != "" {
		httpStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.Target, nil)
		out := &HTTPEgressOutcome{Target: opts.Target}
		if err != nil {
			out.Error = err.Error()
		} else {
			client := &http.Client{Timeout: timeout}
			resp, reqErr := client.Do(req)
			if reqErr != nil {
				out.Error = reqErr.Error()
				out.Errno = extractErrnoName(reqErr)
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				out.StatusCode = resp.StatusCode
				out.OK = true
			}
		}
		cancel()
		out.ElapsedMs = elapsedMs(httpStart)
		res.HTTP = out
	}

	if opts.Addr != "" {
		tcpStart := time.Now()
		conn, err := net.DialTimeout("tcp", opts.Addr, timeout)
		out := &TCPEgressOutcome{Addr: opts.Addr}
		if err != nil {
			out.Error = err.Error()
			out.Errno = extractErrnoName(err)
		} else {
			_ = conn.Close()
			out.OK = true
		}
		out.ElapsedMs = elapsedMs(tcpStart)
		res.TCP = out
	}

	return res, nil
}

// BenignStep records one benign sysadmin operation outcome.
type BenignStep struct {
	Name      string  `json:"name"`
	OK        bool    `json:"ok"`
	ExitCode  int     `json:"exit_code"`
	Detail    string  `json:"detail,omitempty"`
	Error     string  `json:"error,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// BenignAdminOptions configures benign-admin.
type BenignAdminOptions struct {
	Sandbox string
	Jail    *jail.Jail
}

// BenignAdminResult summarizes the benign sysadmin false-positive test suite.
type BenignAdminResult struct {
	Probe          string       `json:"probe"`
	Sandbox        string       `json:"sandbox"`
	OK             bool         `json:"ok"`
	Steps          []BenignStep `json:"steps"`
	TotalElapsedMs float64      `json:"total_elapsed_ms"`
}

// RunBenignAdmin executes normal sysadmin tasks (file creation & SHA-256 hashing,
// tar archive inside sandbox, reading /etc/os-release, and dpkg-query -W bash).
func RunBenignAdmin(opts BenignAdminOptions) (*BenignAdminResult, error) {
	j := opts.Jail
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(opts.Sandbox)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}

	totalStart := time.Now()
	steps := make([]BenignStep, 0, 4)

	// Step 1: Allocate and SHA-256 hash 20 normal text files inside sandbox.
	s1Start := time.Now()
	var fileNames []string
	var step1Err error
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("benign_%02d.txt", i)
		fp, cErr := jail.SafeChildPath(sandboxDir, name)
		if cErr != nil {
			step1Err = cErr
			break
		}
		data := buildRealisticTextPayload(i, 1024)
		if wErr := os.WriteFile(fp, data, 0o644); wErr != nil {
			step1Err = wErr
			break
		}
		sum := sha256.Sum256(data)
		_ = hex.EncodeToString(sum[:])
		fileNames = append(fileNames, name)
	}
	s1 := BenignStep{
		Name:      "alloc_hash_20_files",
		OK:        step1Err == nil,
		Detail:    fmt.Sprintf("files=%d", len(fileNames)),
		ElapsedMs: elapsedMs(s1Start),
	}
	if step1Err != nil {
		s1.ExitCode = 1
		s1.Error = step1Err.Error()
	}
	steps = append(steps, s1)

	// Step 2: Create tar archive inside sandbox.
	s2Start := time.Now()
	tarPath, err := jail.SafeChildPath(sandboxDir, "benign_bundle.tar")
	if err != nil {
		return nil, err
	}
	tarArgs := append([]string{"-cf", tarPath, "-C", sandboxDir}, fileNames...)
	s2 := runBenignCmd("tar_archive", "tar", tarArgs, s2Start)
	steps = append(steps, s2)

	// Step 3: Read /etc/os-release.
	s3Start := time.Now()
	osRel, osErr := os.ReadFile("/etc/os-release")
	s3 := BenignStep{
		Name:      "read_os_release",
		OK:        osErr == nil,
		ElapsedMs: elapsedMs(s3Start),
	}
	if osErr != nil {
		s3.ExitCode = 1
		s3.Error = osErr.Error()
	} else {
		firstLine := strings.SplitN(string(osRel), "\n", 2)[0]
		s3.Detail = strings.TrimSpace(firstLine)
	}
	steps = append(steps, s3)

	// Step 4: Query dpkg for bash package.
	s4Start := time.Now()
	s4 := runBenignCmd("dpkg_query_bash", "dpkg-query", []string{"-W", "bash"}, s4Start)
	steps = append(steps, s4)

	allOK := true
	for _, st := range steps {
		if !st.OK {
			allOK = false
			break
		}
	}

	return &BenignAdminResult{
		Probe:          "benign-admin",
		Sandbox:        sandboxDir,
		OK:             allOK,
		Steps:          steps,
		TotalElapsedMs: elapsedMs(totalStart),
	}, nil
}

func runBenignCmd(name, bin string, args []string, start time.Time) BenignStep {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	st := BenignStep{
		Name:      name,
		OK:        err == nil,
		Detail:    strings.TrimSpace(string(out)),
		ElapsedMs: elapsedMs(start),
	}
	if err != nil {
		st.Error = err.Error()
		if cmd.ProcessState != nil {
			st.ExitCode = cmd.ProcessState.ExitCode()
		} else {
			st.ExitCode = 1
		}
	}
	return st
}

func validateProgressPath(progress string, sandboxJail *jail.Jail) error {
	if strings.TrimSpace(progress) == "" {
		return nil
	}
	if _, err := sandboxJail.Validate(progress); err == nil {
		return nil
	}
	// Allow progress logs in /tmp (or os.TempDir() on non-Linux test hosts) so
	// callers can persist JSONL logs outside an encrypted/wiped sandbox subdir.
	tmpRoots := []string{"/tmp"}
	if runtime.GOOS != "linux" {
		tmpRoots = append(tmpRoots, os.TempDir())
	}
	tmpJail := &jail.Jail{AllowedRoots: tmpRoots}
	if _, err := tmpJail.Validate(progress); err != nil {
		return fmt.Errorf("progress path %q rejected by jail: %w", progress, err)
	}
	return nil
}

func buildRealisticTextPayload(seed, size int) []byte {
	base := fmt.Sprintf(
		"2026-11-21T18:50:%02dZ service=billing-worker doc_id=%05d status=ok "+
			"message=\"Routine operational telemetry snapshot for resilient system verification; "+
			"contains standard ASCII prose, punctuation, and structured key-value fields.\"\n",
		seed%60, seed,
	)
	out := make([]byte, 0, size)
	for len(out) < size {
		out = append(out, base...)
	}
	return out[:size]
}

func countLockedFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".locked") {
			n++
		}
	}
	return n
}

func extractErrnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errnoString(errno)
	}
	return ""
}

func elapsedMs(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func round4(v float64) float64 {
	return float64(int(v*10000+0.5)) / 10000
}
