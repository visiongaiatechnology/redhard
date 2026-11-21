//go:build !linux

package probe

import (
	"fmt"
	"os"
	"syscall"

	"vgt-hardred/probes/internal/jail"
)

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

// RunMemfdExec is only supported on Linux.
func RunMemfdExec() *ExecOutcome {
	return &ExecOutcome{
		Probe:    "memfd-exec",
		OK:       false,
		ExitCode: -1,
		Error:    "memfd-exec requires linux",
	}
}

// RunShmExec is only supported on Linux.
func RunShmExec(sandbox string, j *jail.Jail) (*ExecOutcome, error) {
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	if _, err := j.Validate(sandbox); err != nil {
		return nil, err
	}
	return &ExecOutcome{
		Probe:    "shm-exec",
		Target:   sandbox,
		OK:       false,
		ExitCode: -1,
		Error:    "shm-exec requires linux",
	}, nil
}

// RunTmpExec is only supported on Linux.
func RunTmpExec(sandbox string, j *jail.Jail) (*ExecOutcome, error) {
	if j == nil {
		j = jail.DefaultSandboxJail()
	}
	if _, err := j.Validate(sandbox); err != nil {
		return nil, err
	}
	return &ExecOutcome{
		Probe:    "tmp-exec",
		Target:   sandbox,
		OK:       false,
		ExitCode: -1,
		Error:    "tmp-exec requires linux",
	}, nil
}

// RunLPEProbe is only supported on Linux.
func RunLPEProbe(includeCanary bool) *LPEProbeResult {
	return &LPEProbeResult{
		Probe: "lpe-probe",
		SCTPSocket: LPECheck{
			Detail: "lpe-probe requires linux",
			Error:  "unsupported OS",
		},
	}
}

// RunInternalPtraceChild is only supported on Linux.
func RunInternalPtraceChild() int {
	return 1
}

// InspectWaitStatus decodes non-Linux process wait status.
func InspectWaitStatus(state *os.ProcessState) ChildStatus {
	if state == nil {
		return ChildStatus{Summary: "unknown (nil ProcessState)"}
	}
	return ChildStatus{
		Exited:   state.Exited(),
		ExitCode: state.ExitCode(),
		Summary:  fmt.Sprintf("exited %d", state.ExitCode()),
	}
}

func errnoString(errno syscall.Errno) string {
	return fmt.Sprintf("ERRNO_%d", int(errno))
}
