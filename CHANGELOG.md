# Changelog — VGT HardRed (`RedHard`)

All notable changes to the **VGT HardRed** Linux Security Benchmark Suite are documented in this file.

> **Security Boundary Notice (`V1.3` Private Tier):** The **REDHARD ARES** adversarial campaign engine and the **Anti-Spyware / Anti-Rootkit (`S16`–`S20`)** probe module from internal V1.3 are intentionally excluded from public releases to prevent misuse. Public **`v1.1.0`** backports all safe V1.3 standard engine, adapter, clock calibration, and stability fixes for `S01`–`S15` benchmarking. Reputable security researchers and penetration testers may request vetted V1.3 access via [GitHub Issues](https://github.com/visiongaiatechnology/redhard/issues) or the encrypted form at [visiongaiatechnology.de](https://visiongaiatechnology.de).

## [1.1.0] — 2026-11-26

### Added & Fixed (Safe V1.3 Core Backports — Standard Domains `S01`–`S15`, No ARES / No Anti-Spyware)
- **Sub-Millisecond Clock-Skew Calibration & `ssh_timed()` (`vgt_hardred/vm_control.py`, `adapters/*`):**
  - Replaced one-shot SSH latency assumptions with persistent SSH stdio ping (`_measure_clock_offset_pipe`, `<3 ms` RTT) and minimum-RTT NTP midpoint selection (`measure_clock_offset`) plus automatic invalidation on hypervisor snapshot restore.
  - Added `ssh_timed()`, `AdapterCursor.vm_clock_offset`, `vm_t0_epoch`, `effective_t0_epoch()`, and `compute_event_ttfa_ms()` across `baseline`, `gedefense`, `wazuh`, and `crowdsec` adapters so sub-second TTFA measurements stay unbiased on host/guest clock drift.
  - Added `docker:` container telemetry support in `read_process_stats()`, `attacker_source_ip` configuration, and 3-attempt SSH retries in `ensure_sandboxes()`.
- **GeDefense `6.3.0` Telemetry & Malware Inode Parity (`adapters/gedefense.py`, `runners/malware_runner.py`):**
  - Ignored non-blocking `xdr.sbc_correlated` and `xdr.bpf_guard_tolerated` info events in `diff_snapshots()` so GeDefense 6.3.0 telemetry triggers zero false alarms.
  - Added `BLOCKED_INODE` (`PermissionError`) detection in `malware_runner.py` alongside `QUARANTINED` to accurately verify `MALWARE_DENIED_INODES` kernel enforcement.
- **Additional Standard Contender Adapters (`adapters/safeline.py`, `oss_stack.py`, `oss_safeline.py`):**
  - Added standard `S01`–`S15` telemetry adapters for **Chaitin SafeLine WAF CE**, **OSS Best-of-Breed** (ModSecurity CRS + Suricata + Tetragon + ClamAV), and **OSS + SafeLine WAF**.
- **Scoring Accuracy, Stage Resume & Reliability (`scoring.py`, `cli.py`, `runners/*`):**
  - Restricted Prevention TPR denominators in `scoring.py` to cases with `expected_prevention=True` so detection-only cases (e.g., `EP-ART-*`) do not distort active prevention scores.
  - Added `--resume` stage-level checkpointing (`_deserialize_case_results` / `.stage_checkpoint.json`) across stages `1/6`–`6/6`, increased SSH/Lynis compliance timeouts (`420 s`), added progress-file retry in `endpoint_runner`, and guarded `HTTPError` payload reads in `waf_runner`.
  - Expanded unit regression suite (`tests/test_hardred.py`, `15` tests).

## [1.0.1] — 2026-11-22

### Fixed
- **Go Network/WAF Probe (`hardred-netbench`):** Replaced locale-sensitive substring checks for refused connections with OS-error matching (`syscall.ECONNREFUSED`), added per-attempt `SetDeadline` timeouts and early-abort handling for SSH brute-force floods so throttled targets do not stall the benchmark.
- **Adapter Event & State Isolation (`gedefense`, `crowdsec`):** Preserved baseline HTTP keep-alive connections cleanly, isolated HTTP `429` rate-limit handling from genuine baseline unavailability, ignored non-blocking `titan_exec.policy_applied` telemetry events, filtered alerts/chains cleanly across attack phases via `chain_id` diffing (GeDefense) and alert ID isolation (CrowdSec).
- **WAF, Endpoint, Malware & Compliance Runners:** Batched strike/state resets cleanly in `waf_runner`, halted GoTestWAF early on active IP/rate bans instead of burning full timeouts, added StyX settle and OpenSSH kill-code handling in `endpoint_runner`, aligned `chmod 755` UMASK parity in `malware_runner`, and wrapped `lynis` `cd` execution inside `sudo /bin/sh -c` in `compliance_runner`.
- **CLI & Unit Tests:** Updated orchestration helpers in `vgt_hardred/cli.py` and expanded regression coverage in `tests/test_hardred.py` and `probes/cmd/hardred-netbench/main_test.go`.

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
