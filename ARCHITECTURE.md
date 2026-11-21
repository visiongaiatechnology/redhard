# VGT HardRed (RedHard) — Architecture & Methodology Specification

**Version:** `1.0.0`  
**License:** `AGPL-3.0-only` (First-Party Code) · Upstream OSI Licenses for Third-Party Suites ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md))  
**Scope:** Universal, Snapshot-Isolated Multi-Domain Linux Security Benchmark & 4-Axis Evaluation Framework

---

## 1. Architectural Principles & Trust Boundaries

1. **Strict Dual-Plane Network Isolation (Control-Plane vs. Attack-Plane):**
   - **Control-Plane (`eth0` / NAT SSH `127.0.0.1:2222 -> 10.0.2.2`):** Reserved exclusively for orchestrator command execution, telemetry cursor capture, and system health metrics. Even if a security product under test (`SUT`) drops or blackholes the attacker IP at XDP, nftables, iptables, or L7 proxy layers, the out-of-band telemetry and control channel remains completely unaffected.
   - **Attack-Plane (`eth1` / Host-Only Network `192.168.56.1 -> 192.168.56.50`):** Carries all HTTP/HTTPS application attacks, credential sprays, TCP port scans, velocity floods, and TLS handshakes. The attacker source IP (`192.168.56.1`) is never added to any management allowlist.

2. **Deterministic Snapshot Isolation:**
   - Every contender evaluation begins from a clean, cold-restored hypervisor snapshot (`VBoxManage snapshot <vm> restore <snapshot>`).
   - No two security engines ever run concurrently on the same live state, preventing cross-engine interference, lingering kernel eBPF/iptables state, or cache pollution.

3. **Zero-Dependency First-Party Core + Unmodified OSI Upstream Suites:**
   - The Python orchestrator (`vgt_hardred/`) uses the Python 3.11+ standard library only (`dependencies = []`).
   - High-speed endpoint kernel probes (`hardred-probe`) and network stress engines (`hardred-netbench`) are compiled as static, zero-CGO Go binaries (`probes/`).
   - Industry-standard open-source test corpora (`GoTestWAF`, `go-ftw`, `Falco event-generator`, `Atomic Red Team`, `Lynis`, `ClamAV testfiles`) are invoked at pinned upstream commits without modifying their test definitions.

4. **Fail-Closed Sandbox Jailing:**
   - Destructive-looking behavioral simulations (AES-256-GCM encryption bursts, 600-file rename/wipe storms, child-lineage tests, dropper executions) are strictly confined by `probes/internal/jail/jail.go` to `/tmp/hardred-sandbox` and `/dev/shm/hardred-sandbox`. Any relative path, `..` traversal, symlink escape, or path outside the canonical sandbox roots is rejected before file I/O occurs.

---

## 2. The Six Evaluation Domains (`configs/benchmark_matrix.json`)

| Domain ID | Weight | Focus Area | Primary Probes & Upstream Suites |
| :--- | :---: | :--- | :--- |
| `hardred-waf` | `25 %` | SQLi, comment obfuscation, XSS, LFI, double-encoding, RCE, PHP webshells, SSTI, XXE, Cloud Metadata SSRF, scanner recon, oversized body inspection + 8 benign HTTP controls | `waf_runner.py`, `GoTestWAF`, `go-ftw` |
| `hardred-netids` | `20 %` | HTTP credential spraying, SSH brute-force ban timing, high-concurrency HTTP velocity floods, 16-port TCP connect scans + 2 benign HTTP/TLS controls | `hardred-netbench` (`portscan`, `rate-burst`, `ssh-spray`), `netids_runner.py` |
| `hardred-endpoint` | `35 %` | Fileless `memfd_create` exec, `/dev/shm` & `/tmp` untrusted ELF execution, kernel LPE (`SCTP`/`DCCP`/`AF_PACKET`/`ptrace`), AES-256-GCM ransomware burst (120 files), rapid rename/wiper storm (600 files), child-process lineage kill, Cgroup outbound C2 egress, Falco syscalls, Atomic Red Team Linux TTPs + 2 benign admin controls | `hardred-probe`, `Falco event-generator`, `Atomic Red Team`, `endpoint_runner.py` |
| `hardred-malware` | `10 %` | On-disk EICAR drop, inline HTTP binary EICAR upload, 8-layer nested ZIP wrapper + ClamAV test archive + 1 benign signed asset control | `malware_runner.py`, `clamav-testfiles` |
| `hardred-compliance` | `10 %` | Host hardening posture and active Linux Kernel Security Modules (`/sys/kernel/security/lsm`) | `Lynis 3.1.8`, `compliance_runner.py` |
| `hardred-perf` | `Axis 4` | HTTP RPS & `p50`/`p95`/`p99` latency delta vs. baseline, `sysbench` CPU throughput, `fio` random-write `fsync` IOPS & `p99` latency, security daemon RSS memory (MiB) & CPU (%) | `hardred-netbench http-bench`, `sysbench`, `fio`, `perf_runner.py` |

---

## 3. Four-Axis Scoring Model (`vgt_hardred/scoring.py`)

### 3.1 Per-Domain Score (`0–100`)
Each active security domain separates **Detection TPR** (telemetry/alert emitted within the time window) from **Prevention TPR** (attack blocked, dropped, denied, or process terminated prior to completion), combined with **Balanced Accuracy** and **Alert Context Maturity (`0–3`)**:

$$\text{DomainScore} = 100 \times \left( 0.30 \cdot \text{TPR}_{\text{det}} + 0.45 \cdot \text{TPR}_{\text{prev}} + 0.15 \cdot \text{BalancedAcc} + 0.10 \cdot \frac{\text{ContextMaturity}}{3.0} \right)$$

### 3.2 Overall Composite Score (`0–100`)
$$\text{OverallScore} = 0.45 \cdot \text{Axis}_1 + 0.20 \cdot \text{Axis}_2 + 0.20 \cdot \text{Axis}_3 + 0.15 \cdot \text{Axis}_4$$

- **Axis 1 — Security Efficacy (`45 %`):** Weighted average across `hardred-endpoint` (`35 %`), `hardred-waf` (`25 %`), `hardred-netids` (`20 %`), `hardred-malware` (`10 %`), and `hardred-compliance` (`10 %`).
- **Axis 2 — False-Positive Resilience & AMTSO/WCP Gates (`20 %`):**
  - Penalizes both benign alert noise ($\text{FPR}_{\text{det}} \times 200$) and false blocks ($\text{FPR}_{\text{prot}} \times 600$).
  - **Hard Gate Criteria:**
    - `FAIL`: Endpoint Protection FPR $> 0.0\%$ **or** WAF Protection FPR $> 1.0\%$.
    - `CONDITIONAL`: Unprotected baseline target **or** Endpoint/WAF Detection FPR $> 5.0\%$.
    - `PASS`: All false-positive gates satisfied.
- **Axis 3 — Reaction Latency & Pre-Kill Damage Containment (`20 %`):**
  - Combines logarithmic **Time-to-First-Alert (TTFA)** scoring ($\le 50\text{ ms} \rightarrow 100$) with `55 %` weight and **Ransomware Pre-Kill Containment** ($1 - \text{DamageRatio}$ across the 120-file AES burst, 600-file rename storm, and 60-file child lineage test) with `45 %` weight.
- **Axis 4 — Operational Overhead & Stability (`15 %`):**
  - Measures HTTP `p95` latency delta, `fio` random-write IOPS delta, security daemon RSS footprint (MiB), and CPU utilization relative to the clean baseline snapshot.

---

## 4. Standardized Forensic & Audit Exports (`vgt_hardred/exporters.py`)

- **OCSF v1.9.0 JSONL (`<contender>.ocsf.jsonl`):** Detection Finding (`class_uid: 2004`) records with MITRE ATT&CK metadata and disposition mapping.
- **SARIF v2.1.0 JSON (`<contender>.sarif.json`):** Static/Runtime Analysis Results Format for CI/CD and GitHub Code Scanning integration.
- **MITRE ATT&CK Navigator Layer v4.5 (`<contender>.attack_layer.json`):** Visual color-coded matrix (`Green` = Prevented, `Amber` = Detected Only, `Red` = Missed).
- **VGT Glass 2100 Dashboard (`VGT_HardRed_Dashboard.html`) & Markdown Report (`FINAL_BENCHMARK_REPORT.md`).**
