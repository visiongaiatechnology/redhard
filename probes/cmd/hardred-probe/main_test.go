package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vgt-hardred/probes/internal/jail"
	"vgt-hardred/probes/internal/metrics"
	"vgt-hardred/probes/internal/probe"
)

func TestDefaultSandboxJailRejectsUnsafePaths(t *testing.T) {
	j := jail.DefaultSandboxJail()
	rejected := []string{
		"",
		"   ",
		"/",
		"/etc",
		"/etc/passwd",
		"/var/log",
		"/tmp",
		"/tmp/",
		"/tmp/other",
		"/dev/shm",
		"/dev/shm/other",
		"/tmp/hardred-sandbox/../etc",
		"/tmp/hardred-sandbox/aes/../../etc/shadow",
		"/dev/shm/hardred-sandbox/../../root",
		"relative/sandbox",
		`C:\Windows\System32`,
	}
	for _, p := range rejected {
		if got, err := j.Validate(p); err == nil {
			t.Fatalf("expected jail.Validate(%q) to fail, got %q", p, got)
		}
	}

	accepted := []string{
		"/tmp/hardred-sandbox",
		"/tmp/hardred-sandbox/aes",
		"/tmp/hardred-sandbox/storm/sub",
		"/dev/shm/hardred-sandbox",
		"/dev/shm/hardred-sandbox/exec",
	}
	for _, p := range accepted {
		if _, err := j.Validate(p); err != nil {
			t.Fatalf("expected jail.Validate(%q) to succeed, got error: %v", p, err)
		}
	}
}

func TestJailRejectsSymlinkEscapeOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX symlink escape test runs on Linux")
	}
	root := t.TempDir()
	j := &jail.Jail{AllowedRoots: []string{root}}
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink("/etc", escapeLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if got, err := j.Validate(filepath.Join(escapeLink, "sub")); err == nil {
		t.Fatalf("expected symlink escape to be rejected, got %q", got)
	}
}

func TestProbesFailClosedOnRejectedSandbox(t *testing.T) {
	for _, bad := range []string{"/", "/etc", "/tmp"} {
		if _, err := probe.RunAESRansom(probe.AESRansomOptions{Sandbox: bad, Count: 1}); err == nil {
			t.Fatalf("RunAESRansom(%q) should fail closed", bad)
		}
		if _, err := probe.RunRenameStorm(probe.RenameStormOptions{Sandbox: bad, Count: 1, Batch: 1}); err == nil {
			t.Fatalf("RunRenameStorm(%q) should fail closed", bad)
		}
		if _, err := probe.RunChildKillTest(probe.ChildKillOptions{Sandbox: bad, Count: 1}); err == nil {
			t.Fatalf("RunChildKillTest(%q) should fail closed", bad)
		}
		if _, err := probe.RunBenignAdmin(probe.BenignAdminOptions{Sandbox: bad}); err == nil {
			t.Fatalf("RunBenignAdmin(%q) should fail closed", bad)
		}
	}
	if code := run([]string{"aes-ransom", "-sandbox", "/etc", "-count", "1"}); code == 0 {
		t.Fatalf("CLI aes-ransom -sandbox /etc should return non-zero exit code")
	}
}

func TestAESRansomEntropyAndProgressPersistence(t *testing.T) {
	root := t.TempDir()
	sandbox := filepath.Join(root, "aes")
	progress := filepath.Join(root, "aes_progress.jsonl")
	testJail := &jail.Jail{AllowedRoots: []string{root}}

	res, err := probe.RunAESRansom(probe.AESRansomOptions{
		Sandbox:  sandbox,
		Count:    6,
		DelayMs:  0,
		Progress: progress,
		Jail:     testJail,
	})
	if err != nil {
		t.Fatalf("RunAESRansom failed: %v", err)
	}
	if res.CompletedCount != 6 {
		t.Fatalf("expected 6 completed files, got %d", res.CompletedCount)
	}
	if res.MeanEntropyPre >= 6.0 {
		t.Fatalf("expected realistic text pre-entropy < 6.0, got %v", res.MeanEntropyPre)
	}
	if res.MeanEntropyPost <= 7.5 {
		t.Fatalf("expected AES-GCM ciphertext entropy > 7.5, got %v", res.MeanEntropyPost)
	}

	entries, err := os.ReadDir(sandbox)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	lockedCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".txt") {
			t.Fatalf("plaintext file %s should have been deleted", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".locked") {
			lockedCount++
		}
	}
	if lockedCount != 6 {
		t.Fatalf("expected 6 .locked files, got %d", lockedCount)
	}

	f, err := os.Open(progress)
	if err != nil {
		t.Fatalf("open progress: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		var row probe.AESProgressEntry
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("invalid JSONL line %d: %v", lineCount, err)
		}
		if row.Idx != lineCount {
			t.Fatalf("expected idx %d, got %d", lineCount, row.Idx)
		}
		if row.EntropyAfter <= 7.5 {
			t.Fatalf("line %d entropy_after=%v <= 7.5", lineCount, row.EntropyAfter)
		}
		if _, err := os.Stat(row.File); err != nil {
			t.Fatalf("locked file %s missing: %v", row.File, err)
		}
		lineCount++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	if lineCount != 6 {
		t.Fatalf("expected 6 JSONL progress lines, got %d", lineCount)
	}
}

func TestRenameStormBatchedProgress(t *testing.T) {
	root := t.TempDir()
	sandbox := filepath.Join(root, "storm")
	progress := filepath.Join(root, "storm.jsonl")
	testJail := &jail.Jail{AllowedRoots: []string{root}}

	res, err := probe.RunRenameStorm(probe.RenameStormOptions{
		Sandbox:  sandbox,
		Count:    25,
		Batch:    10,
		DelayMs:  0,
		Progress: progress,
		Jail:     testJail,
	})
	if err != nil {
		t.Fatalf("RunRenameStorm failed: %v", err)
	}
	if res.CompletedCount != 25 || res.Batches != 3 {
		t.Fatalf("unexpected result: %+v", res)
	}

	raw, err := os.ReadFile(progress)
	if err != nil {
		t.Fatalf("read progress: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 batch lines, got %d", len(lines))
	}
	var last probe.StormBatchEntry
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil {
		t.Fatalf("unmarshal batch 3: %v", err)
	}
	if last.Completed != 25 || last.BatchFiles != 5 {
		t.Fatalf("unexpected final batch: %+v", last)
	}
}

func TestEgressProbeLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

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

	res, err := probe.RunEgressProbe(probe.EgressProbeOptions{
		Target:    srv.URL,
		Addr:      ln.Addr().String(),
		TimeoutMs: 2000,
	})
	if err != nil {
		t.Fatalf("RunEgressProbe: %v", err)
	}
	if res.HTTP == nil || !res.HTTP.OK || res.HTTP.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected HTTP outcome: %+v", res.HTTP)
	}
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("unexpected TCP outcome: %+v", res.TCP)
	}
}

func TestShannonEntropyBounds(t *testing.T) {
	zeros := make([]byte, 1024)
	if e := metrics.ShannonEntropy(zeros); e != 0 {
		t.Fatalf("expected 0 entropy for constant bytes, got %v", e)
	}
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	if e := metrics.ShannonEntropy(allBytes); e != 8.0 {
		t.Fatalf("expected 8.0 entropy for uniform byte distribution, got %v", e)
	}
}

func TestCLIHelp(t *testing.T) {
	if code := run([]string{"--help"}); code != 0 {
		t.Fatalf("expected --help to return 0, got %d", code)
	}
	if code := run(nil); code == 0 {
		t.Fatalf("expected empty args to return non-zero")
	}
}
