package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"vgt-hardred/probes/internal/probe"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" {
		printUsage()
		if len(args) == 0 {
			return 2
		}
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "--internal-ptrace-child":
		return probe.RunInternalPtraceChild()
	case "aes-ransom":
		return cmdAESRansom(subArgs)
	case "rename-storm":
		return cmdRenameStorm(subArgs)
	case "child-kill-test":
		return cmdChildKillTest(subArgs)
	case "memfd-exec":
		return cmdMemfdExec(subArgs)
	case "shm-exec":
		return cmdShmExec(subArgs)
	case "tmp-exec":
		return cmdTmpExec(subArgs)
	case "lpe-probe":
		return cmdLPEProbe(subArgs)
	case "egress-probe":
		return cmdEgressProbe(subArgs)
	case "benign-admin":
		return cmdBenignAdmin(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		printUsage()
		return 2
	}
}

func cmdAESRansom(args []string) int {
	fs := flag.NewFlagSet("aes-ransom", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/tmp/hardred-sandbox/aes", "jailed sandbox directory")
	count := fs.Int("count", 120, "number of 4KB text files to create and encrypt")
	delayMs := fs.Int("delay-ms", 15, "delay between files in milliseconds")
	progress := fs.String("progress", "", "optional JSONL progress file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunAESRansom(probe.AESRansomOptions{
		Sandbox:  *sandbox,
		Count:    *count,
		DelayMs:  *delayMs,
		Progress: *progress,
	})
	if err != nil {
		return failJSON("aes-ransom", err)
	}
	return writeJSON(res)
}

func cmdRenameStorm(args []string) int {
	fs := flag.NewFlagSet("rename-storm", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/tmp/hardred-sandbox/storm", "jailed sandbox directory")
	count := fs.Int("count", 600, "total files to write and rename")
	batch := fs.Int("batch", 50, "files per batch")
	delayMs := fs.Int("delay-ms", 5, "delay between batches in milliseconds")
	progress := fs.String("progress", "", "optional JSONL progress file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunRenameStorm(probe.RenameStormOptions{
		Sandbox:  *sandbox,
		Count:    *count,
		Batch:    *batch,
		DelayMs:  *delayMs,
		Progress: *progress,
	})
	if err != nil {
		return failJSON("rename-storm", err)
	}
	return writeJSON(res)
}

func cmdChildKillTest(args []string) int {
	fs := flag.NewFlagSet("child-kill-test", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/tmp/hardred-sandbox/child", "jailed sandbox directory")
	count := fs.Int("count", 60, "number of files for child aes-ransom")
	delayMs := fs.Int("delay-ms", 15, "delay between files in milliseconds")
	progress := fs.String("progress", "", "optional JSONL progress file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunChildKillTest(probe.ChildKillOptions{
		Sandbox:  *sandbox,
		Count:    *count,
		DelayMs:  *delayMs,
		Progress: *progress,
	})
	if err != nil {
		return failJSON("child-kill-test", err)
	}
	return writeJSON(res)
}

func cmdMemfdExec(args []string) int {
	fs := flag.NewFlagSet("memfd-exec", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return writeJSON(probe.RunMemfdExec())
}

func cmdShmExec(args []string) int {
	fs := flag.NewFlagSet("shm-exec", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/dev/shm/hardred-sandbox", "jailed /dev/shm sandbox directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunShmExec(*sandbox, nil)
	if err != nil {
		return failJSON("shm-exec", err)
	}
	return writeJSON(res)
}

func cmdTmpExec(args []string) int {
	fs := flag.NewFlagSet("tmp-exec", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/tmp/hardred-sandbox", "jailed /tmp sandbox directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunTmpExec(*sandbox, nil)
	if err != nil {
		return failJSON("tmp-exec", err)
	}
	return writeJSON(res)
}

func cmdLPEProbe(args []string) int {
	fs := flag.NewFlagSet("lpe-probe", flag.ContinueOnError)
	includeCanary := fs.Bool("include-canary", false, "also attempt read-only open of /var/lib/vgt/gedefense/canaries/.aws_credentials")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return writeJSON(probe.RunLPEProbe(*includeCanary))
}

func cmdEgressProbe(args []string) int {
	fs := flag.NewFlagSet("egress-probe", flag.ContinueOnError)
	target := fs.String("target", "http://1.1.1.1/", "HTTP URL target for egress test")
	addr := fs.String("addr", "1.1.1.1:80", "TCP host:port target for egress test")
	timeoutMs := fs.Int("timeout-ms", 3000, "timeout in milliseconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunEgressProbe(probe.EgressProbeOptions{
		Target:    *target,
		Addr:      *addr,
		TimeoutMs: *timeoutMs,
	})
	if err != nil {
		return failJSON("egress-probe", err)
	}
	return writeJSON(res)
}

func cmdBenignAdmin(args []string) int {
	fs := flag.NewFlagSet("benign-admin", flag.ContinueOnError)
	sandbox := fs.String("sandbox", "/tmp/hardred-sandbox/benign", "jailed sandbox directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := probe.RunBenignAdmin(probe.BenignAdminOptions{Sandbox: *sandbox})
	if err != nil {
		return failJSON("benign-admin", err)
	}
	if !res.OK {
		_ = writeJSON(res)
		return 1
	}
	return writeJSON(res)
}

func writeJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
		return 1
	}
	return 0
}

func failJSON(sub string, err error) int {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
		"probe": sub,
		"ok":    false,
		"error": err.Error(),
	})
	return 1
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `hardred-probe - VGT HardRed host security benchmark probe

Usage:
  hardred-probe <subcommand> [flags]

Subcommands:
  aes-ransom       Create 4KB text files and AES-256-GCM encrypt them inside jailed sandbox
  rename-storm     Execute batched write/rename storm inside jailed sandbox
  child-kill-test  Spawn child aes-ransom and report signal/exit status and file damage
  memfd-exec       Execute a harmless /bin/sh echo script via memfd_create + /proc/self/fd
  shm-exec         Execute a harmless /bin/sh script inside /dev/shm/hardred-sandbox
  tmp-exec         Execute a copied binary (/bin/true) inside /tmp/hardred-sandbox
  lpe-probe        Probe safe non-destructive LPE/kernel surfaces (SCTP, DCCP, AF_PACKET, ptrace, /etc/shadow)
  egress-probe     Test outbound HTTP GET and TCP connect within timeout
  benign-admin     Execute benign sysadmin actions (tar, /etc/os-release, dpkg-query, SHA-256)`)
}
