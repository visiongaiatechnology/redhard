//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"vgt-hardred/probes/internal/jail"
)

// RunMemfdExec creates an anonymous memfd, writes a tiny /bin/sh echo script,
// and attempts to execute /proc/self/fd/<fd>.
func RunMemfdExec() *ExecOutcome {
	start := time.Now()
	out := &ExecOutcome{
		Probe:    "memfd-exec",
		ExitCode: -1,
	}

	fd, err := unix.MemfdCreate("hardred_memfd", 0)
	if err != nil {
		out.Error = fmt.Sprintf("memfd_create: %v", err)
		out.Errno = extractErrnoName(err)
		out.ElapsedMs = elapsedMs(start)
		return out
	}
	defer unix.Close(fd)

	script := []byte("#!/bin/sh\necho MEMFD_OK\n")
	if _, err := unix.Write(fd, script); err != nil {
		out.Error = fmt.Sprintf("write memfd: %v", err)
		out.Errno = extractErrnoName(err)
		out.ElapsedMs = elapsedMs(start)
		return out
	}
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		out.Error = fmt.Sprintf("seek memfd: %v", err)
		out.Errno = extractErrnoName(err)
		out.ElapsedMs = elapsedMs(start)
		return out
	}

	target := fmt.Sprintf("/proc/self/fd/%d", fd)
	out.Target = target
	runExecTarget(target, out, start)
	return out
}

// RunShmExec writes a tiny harmless /bin/sh script inside the jailed /dev/shm sandbox and tries to execute it.
func RunShmExec(sandbox string, j *jail.Jail) (*ExecOutcome, error) {
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(sandbox)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}
	scriptPath, err := jail.SafeChildPath(sandboxDir, "shm_exec_test.sh")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho SHM_OK\n"), 0o700); err != nil {
		return nil, fmt.Errorf("write shm script: %w", err)
	}
	if err := os.Chmod(scriptPath, 0o700); err != nil {
		return nil, fmt.Errorf("chmod shm script: %w", err)
	}

	start := time.Now()
	out := &ExecOutcome{
		Probe:    "shm-exec",
		Target:   scriptPath,
		ExitCode: -1,
	}
	runExecTarget(scriptPath, out, start)
	return out, nil
}

// RunTmpExec copies /bin/true into the jailed /tmp sandbox, marks it 0755, and attempts execution.
func RunTmpExec(sandbox string, j *jail.Jail) (*ExecOutcome, error) {
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	sandboxDir, err := j.Validate(sandbox)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox dir: %w", err)
	}

	srcBin := "/bin/true"
	if _, err := os.Stat(srcBin); err != nil {
		srcBin = "/usr/bin/true"
	}
	data, err := os.ReadFile(srcBin)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", srcBin, err)
	}

	dstPath, err := jail.SafeChildPath(sandboxDir, "untrusted_exec_test")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(dstPath, data, 0o755); err != nil {
		return nil, fmt.Errorf("write %s: %w", dstPath, err)
	}
	if err := os.Chmod(dstPath, 0o755); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", dstPath, err)
	}

	start := time.Now()
	out := &ExecOutcome{
		Probe:    "tmp-exec",
		Target:   dstPath,
		ExitCode: -1,
	}
	runExecTarget(dstPath, out, start)
	return out, nil
}

func runExecTarget(target string, out *ExecOutcome, start time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out.ElapsedMs = elapsedMs(start)
	out.Stdout = strings.TrimSpace(stdout.String())
	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		out.OK = false
		out.Errno = extractErrnoName(err)
		errMsg := err.Error()
		if se := strings.TrimSpace(stderr.String()); se != "" {
			errMsg = fmt.Sprintf("%s (%s)", errMsg, se)
		}
		out.Error = errMsg
		return
	}
	out.OK = true
}

// LPECheck records one non-destructive kernel/LPE surface check.
type LPECheck struct {
	Attempted bool    `json:"attempted"`
	OK        bool    `json:"ok"`
	Errno     string  `json:"errno,omitempty"`
	Error     string  `json:"error,omitempty"`
	Detail    string  `json:"detail,omitempty"`
	BytesRead int     `json:"bytes_read,omitempty"`
	ElapsedMs float64 `json:"elapsed_ms"`
}

// LPEProbeResult summarizes all lpe-probe checks.
type LPEProbeResult struct {
	Probe          string   `json:"probe"`
	SCTPSocket     LPECheck `json:"sctp_socket"`
	DCCPSocket     LPECheck `json:"dccp_socket"`
	PacketRaw      LPECheck `json:"packet_raw_socket"`
	PtraceTraceme  LPECheck `json:"ptrace_traceme"`
	EtcShadowOpen  LPECheck `json:"etc_shadow_open"`
	CanaryAWSRead  LPECheck `json:"canary_aws_read"`
	TotalElapsedMs float64  `json:"total_elapsed_ms"`
}

// RunLPEProbe safely probes kernel/LPE surfaces without exploiting them.
func RunLPEProbe(includeCanary bool) *LPEProbeResult {
	totalStart := time.Now()
	res := &LPEProbeResult{
		Probe:         "lpe-probe",
		SCTPSocket:    probeSocket(unix.AF_INET, unix.SOCK_SEQPACKET, 132, "IPPROTO_SCTP"),
		DCCPSocket:    probeSocket(unix.AF_INET, unix.SOCK_DCCP, 33, "IPPROTO_DCCP"),
		PacketRaw:     probeSocket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)), "AF_PACKET/SOCK_RAW"),
		PtraceTraceme: probePtraceChild(),
		EtcShadowOpen: probeOpenRO("/etc/shadow"),
	}

	if includeCanary {
		res.CanaryAWSRead = probeCanaryRO("/var/lib/vgt/gedefense/canaries/.aws_credentials")
	} else {
		res.CanaryAWSRead = LPECheck{
			Attempted: false,
			OK:        false,
			Detail:    "skipped (pass -include-canary to probe canary)",
		}
	}
	res.TotalElapsedMs = elapsedMs(totalStart)
	return res
}

// RunInternalPtraceChild is invoked via re-exec to safely test PTRACE_TRACEME in a clean child.
func RunInternalPtraceChild() int {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "ERRNO:%s:%v\n", errnoString(syscall.Errno(errno)), errno)
		return 2
	}
	return 0
}

func probeSocket(domain, typ, proto int, label string) LPECheck {
	start := time.Now()
	fd, err := unix.Socket(domain, typ, proto)
	c := LPECheck{
		Attempted: true,
		Detail:    label,
		ElapsedMs: elapsedMs(start),
	}
	if err != nil {
		c.OK = false
		c.Errno = extractErrnoName(err)
		c.Error = err.Error()
		return c
	}
	_ = unix.Close(fd)
	c.OK = true
	return c
}

func probePtraceChild() LPECheck {
	start := time.Now()
	c := LPECheck{Attempted: true, Detail: "PTRACE_TRACEME"}
	exe, err := os.Executable()
	if err != nil {
		c.Error = err.Error()
		c.ElapsedMs = elapsedMs(start)
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--internal-ptrace-child")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	c.ElapsedMs = elapsedMs(start)
	if runErr == nil {
		c.OK = true
		return c
	}
	c.OK = false
	msg := strings.TrimSpace(stderr.String())
	if strings.HasPrefix(msg, "ERRNO:") {
		parts := strings.SplitN(msg, ":", 3)
		if len(parts) >= 2 {
			c.Errno = parts[1]
		}
		if len(parts) == 3 {
			c.Error = parts[2]
		}
	} else {
		c.Errno = extractErrnoName(runErr)
		c.Error = runErr.Error()
	}
	return c
}

func probeOpenRO(target string) LPECheck {
	start := time.Now()
	fd, err := unix.Open(target, unix.O_RDONLY, 0)
	c := LPECheck{
		Attempted: true,
		Detail:    target,
		ElapsedMs: elapsedMs(start),
	}
	if err != nil {
		c.OK = false
		c.Errno = extractErrnoName(err)
		c.Error = err.Error()
		return c
	}
	_ = unix.Close(fd)
	c.OK = true
	return c
}

func probeCanaryRO(target string) LPECheck {
	start := time.Now()
	fd, err := unix.Open(target, unix.O_RDONLY, 0)
	c := LPECheck{
		Attempted: true,
		Detail:    target,
		ElapsedMs: elapsedMs(start),
	}
	if err != nil {
		c.OK = false
		c.Errno = extractErrnoName(err)
		c.Error = err.Error()
		return c
	}
	defer unix.Close(fd)
	var buf [1]byte
	n, rErr := unix.Read(fd, buf[:])
	c.ElapsedMs = elapsedMs(start)
	if rErr != nil {
		c.OK = false
		c.Errno = extractErrnoName(rErr)
		c.Error = rErr.Error()
		return c
	}
	c.OK = true
	c.BytesRead = n
	return c
}

// InspectWaitStatus decodes Linux process wait status into a structured ChildStatus.
func InspectWaitStatus(state *os.ProcessState) ChildStatus {
	if state == nil {
		return ChildStatus{Summary: "unknown (nil ProcessState)"}
	}
	ws, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		return ChildStatus{
			Exited:   state.Exited(),
			ExitCode: state.ExitCode(),
			Summary:  fmt.Sprintf("exited %d", state.ExitCode()),
		}
	}
	cs := ChildStatus{
		Exited:   ws.Exited(),
		ExitCode: ws.ExitStatus(),
		Signaled: ws.Signaled(),
		Stopped:  ws.Stopped(),
	}
	switch {
	case ws.Signaled():
		sig := ws.Signal()
		cs.Signal = unix.SignalName(sig)
		if cs.Signal == "" {
			cs.Signal = sig.String()
		}
		if sig == unix.SIGKILL {
			cs.Summary = "killed (" + cs.Signal + ")"
		} else {
			cs.Summary = "signaled (" + cs.Signal + ")"
		}
	case ws.Stopped():
		sig := ws.StopSignal()
		cs.Signal = unix.SignalName(sig)
		if cs.Signal == "" {
			cs.Signal = sig.String()
		}
		cs.Summary = "stopped (" + cs.Signal + ")"
	case ws.Exited():
		cs.Summary = fmt.Sprintf("exited %d", ws.ExitStatus())
	default:
		cs.Summary = fmt.Sprintf("status 0x%x", uint32(ws))
	}
	return cs
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}

func errnoString(errno syscall.Errno) string {
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return fmt.Sprintf("ERRNO_%d", int(errno))
}

var _ = errors.New
