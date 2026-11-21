package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"vgt-hardred/probes/internal/netbench"
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
	case "http-bench":
		return cmdHTTPBench(subArgs)
	case "rate-burst":
		return cmdRateBurst(subArgs)
	case "portscan":
		return cmdPortScan(subArgs)
	case "ssh-spray":
		return cmdSSHSpray(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		printUsage()
		return 2
	}
}

func cmdHTTPBench(args []string) int {
	fs := flag.NewFlagSet("http-bench", flag.ContinueOnError)
	targetURL := fs.String("url", "http://192.168.56.50/index.php", "target HTTP/HTTPS URL")
	requests := fs.Int("requests", 300, "total HTTP GET requests")
	concurrency := fs.Int("concurrency", 16, "number of concurrent workers")
	timeoutMs := fs.Int("timeout-ms", 5000, "per-request timeout in milliseconds")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := netbench.RunHTTPBench(netbench.HTTPBenchOptions{
		URL:         *targetURL,
		Requests:    *requests,
		Concurrency: *concurrency,
		TimeoutMs:   *timeoutMs,
		Insecure:    *insecure,
	})
	if err != nil {
		return failJSON("http-bench", err)
	}
	return writeJSON(res)
}

func cmdRateBurst(args []string) int {
	fs := flag.NewFlagSet("rate-burst", flag.ContinueOnError)
	targetURL := fs.String("url", "http://192.168.56.50/index.php?burst=1", "target HTTP/HTTPS URL")
	requests := fs.Int("requests", 250, "total burst requests")
	concurrency := fs.Int("concurrency", 32, "concurrent burst workers")
	timeoutMs := fs.Int("timeout-ms", 3000, "per-request timeout in milliseconds")
	recoveryWaitMs := fs.Int("recovery-wait-ms", 3000, "pause before recovery probes in milliseconds")
	recoveryProbes := fs.Int("recovery-probes", 5, "number of sequential recovery probes after pause")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := netbench.RunRateBurst(netbench.RateBurstOptions{
		URL:            *targetURL,
		Requests:       *requests,
		Concurrency:    *concurrency,
		TimeoutMs:      *timeoutMs,
		RecoveryWaitMs: *recoveryWaitMs,
		RecoveryProbes: *recoveryProbes,
		Insecure:       *insecure,
	})
	if err != nil {
		return failJSON("rate-burst", err)
	}
	return writeJSON(res)
}

func cmdPortScan(args []string) int {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)
	host := fs.String("host", "192.168.56.50", "target host IP or hostname")
	portsSpec := fs.String("ports", "21,22,23,25,80,110,139,443,445,3306,3389,5432,6379,8080,8443,9200", "comma-separated TCP ports")
	timeoutMs := fs.Int("timeout-ms", 800, "per-port connect timeout in milliseconds")
	delayMs := fs.Int("delay-ms", 20, "delay between ports in milliseconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ports, err := netbench.ParsePorts(*portsSpec)
	if err != nil {
		return failJSON("portscan", err)
	}
	res, err := netbench.RunPortScan(netbench.PortScanOptions{
		Host:      *host,
		Ports:     ports,
		TimeoutMs: *timeoutMs,
		DelayMs:   *delayMs,
	})
	if err != nil {
		return failJSON("portscan", err)
	}
	return writeJSON(res)
}

func cmdSSHSpray(args []string) int {
	fs := flag.NewFlagSet("ssh-spray", flag.ContinueOnError)
	addr := fs.String("addr", "192.168.56.50:22", "target SSH host:port")
	attempts := fs.Int("attempts", 20, "bounded number of invalid-user SSH attempts")
	delayMs := fs.Int("delay-ms", 100, "delay between attempts in milliseconds")
	timeoutMs := fs.Int("timeout-ms", 3000, "per-attempt timeout in milliseconds")
	userPrefix := fs.String("user-prefix", "hardred_invalid_", "invalid username prefix")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := netbench.RunSSHSpray(netbench.SSHSprayOptions{
		Addr:       *addr,
		Attempts:   *attempts,
		DelayMs:    *delayMs,
		TimeoutMs:  *timeoutMs,
		UserPrefix: *userPrefix,
	})
	if err != nil {
		return failJSON("ssh-spray", err)
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
	fmt.Fprintln(os.Stderr, `hardred-netbench - VGT HardRed network & WAF benchmark tool

Usage:
  hardred-netbench <subcommand> [flags]

Subcommands:
  http-bench   Measure HTTP throughput, status distribution, and p50/p95/p99/max latency
  rate-burst   Burst HTTP requests to locate rate-limit threshold and measure recovery
  portscan     Sequential TCP connect scan tracking open/closed/timeout and mid-scan drops
  ssh-spray    Bounded invalid-user SSH auth attempts to test auth/CrowdSec/XDP response`)
}
