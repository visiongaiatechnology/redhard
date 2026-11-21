# Changelog — VGT HardRed (`RedHard`)

All notable changes to the **VGT HardRed** Linux Security Benchmark Suite are documented in this file.

## [1.0.0] — 2026-11-21

### Added
- **6-Domain Linux Security Benchmark Orchestrator (`vgt_hardred/`):**
  - `hardred-waf`: 14 OWASP/evasion HTTP attack probes, 8 benign HTTP false-positive controls, plus automated `GoTestWAF` (`v0.5.11`) and `go-ftw` corpus integration.
  - `hardred-netids`: HTTP credential spraying, SSH failed-login spray ban verification, high-concurrency HTTP velocity flood, 16-port TCP connect scan, plus 2 benign HTTP/TLS controls.
  - `hardred-endpoint`: Fileless `memfd_create` execution, `/dev/shm` dropper, `/tmp` untrusted ELF execution, kernel LPE socket/ptrace probe, 120-file AES-256-GCM ransomware burst with pre-kill damage tracking, 600-file rapid rename/wipe storm, child-process lineage kill verification, systemd cgroup outbound C2 egress probe, Falco `event-generator` syscall pack, Red Canary `Atomic Red Team` Linux TTPs, plus 2 benign admin controls.
  - `hardred-malware`: On-disk EICAR signature check, inline HTTP binary EICAR upload, 8-layer nested ZIP wrapper + `clamav-testfiles` inspection, plus 1 benign asset control.
  - `hardred-compliance`: Automated `Lynis 3.1.8` hardening index audit and live `/sys/kernel/security/lsm` inspection.
  - `hardred-perf`: HTTP throughput (`RPS`) and `p50`/`p95`/`p99` latency profiling, `sysbench` CPU benchmark, `fio` random-write `fsync` IOPS benchmark, and security daemon RSS/CPU profiler.
- **Static Go Probes (`probes/`):**
  - `hardred-probe` with strict sandbox jail validation (`probes/internal/jail/jail.go`).
  - `hardred-netbench` for deterministic HTTP load, velocity bursts, TCP port scanning, and SSH credential spraying.
- **4-Axis Mathematical Scoring Engine & AMTSO/WCP False-Positive Gates (`vgt_hardred/scoring.py`):**
  - Separated Detection TPR vs. Prevention TPR, Context Maturity (`0–3`), TTFA logarithmic scoring, Pre-Kill Ransomware Damage ratio, and strict `PASS` / `CONDITIONAL` / `FAIL` gating.
- **Pluggable Contender Adapters (`vgt_hardred/adapters/`):**
  - Reference adapters for `baseline`, `gedefense`, `wazuh`, and `crowdsec`, plus open `ContenderAdapter` protocol for arbitrary Linux security suites.
- **Standardized Audit Exports (`vgt_hardred/exporters.py`, `vgt_hardred/report_glass.py`):**
  - OCSF v1.9.0 JSONL, SARIF v2.1.0 JSON, MITRE ATT&CK Navigator v4.5 Layer JSON, CSV comparison tables, and interactive VGT Glass 2100 HTML5 dashboard.
- **Multi-Language Documentation:**
  - Complete 1:1 documentation in English ([README.md](README.md)), German ([README.de.md](README.de.md)), Russian ([README.ru.md](README.ru.md)), and Simplified Chinese ([README.zh.md](README.zh.md)).
