# Third-Party Benchmark Suites & Licensing Notices

## Dual-Layer Licensing Model

1. **First-Party Code (`AGPL-3.0-only`):**
   All original source code, orchestration modules (`vgt_hardred/`), custom Go kernel and network probes (`probes/`), unit tests (`tests/`), bootstrap tooling (`scripts/`), and documentation in this repository are © Vision Gaia Technology (VGT) and licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)** — see [LICENSE](LICENSE).

2. **Third-Party Open-Source Benchmark Suites (Upstream Licenses):**
   `VGT HardRed` orchestrates established, OSI-approved open-source security testing frameworks as unmodified upstream benchmark suites. These third-party tools are fetched and built locally via `python scripts/bootstrap_third_party.py` into `third_party/` (excluded from the Git source repository via `.gitignore`) and remain governed solely by their respective upstream licenses listed below.

---

## 1. GoTestWAF
- **Upstream Repository:** https://github.com/wallarm/gotestwaf
- **License:** MIT
- **Pinned Revision / Tag:** `5daeba073823a57e79ba922beef0c2d92a8dd776` (`v0.5.11`)
- **Role in VGT HardRed:** AppSec / API Security corpus evaluator (`hardred-waf` secondary corpus: OWASP, Community, REST, SOAP, and False-Positive text sets).

## 2. go-ftw (OWASP CRS Framework for Testing WAFs)
- **Upstream Repository:** https://github.com/coreruleset/go-ftw
- **License:** Apache-2.0
- **Pinned Revision:** `84559ca9bce1264981c67c61a1c462cadd86163a`
- **Role in VGT HardRed:** Standard OWASP CoreRuleSet WAF regression testing engine (`third_party/bin/go-ftw`).

## 3. Falco event-generator
- **Upstream Repository:** https://github.com/falcosecurity/event-generator
- **License:** Apache-2.0
- **Pinned Revision:** `07d29365f0d3ba0d160a9d703c914dd293aa27e2`
- **Role in VGT HardRed:** Kernel & syscall runtime behavioral stimulus (`hardred-endpoint`: `syscall.ReadSensitiveFileUntrusted`, `syscall.CreateSymlinkOverSensitiveFiles`, `syscall.PtraceAntiDebugAttempt`).

## 4. Red Canary Atomic Red Team (`atomics/`)
- **Upstream Repository:** https://github.com/redcanaryco/atomic-red-team
- **License:** MIT
- **Pinned Revision:** `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`
- **Role in VGT HardRed:** MITRE ATT&CK Linux technique validation and YAML provenance checks (`hardred-endpoint`: `T1087.001`, `T1059.004`, `T1053.003`, `T1548.001`).

## 5. CISOfy Lynis
- **Upstream Repository:** https://github.com/CISOfy/lynis
- **License:** GPL-3.0
- **Pinned Revision / Version:** `a9527dc768f447bce71205fa3f2b0f78492844c0` (`3.1.8`)
- **Role in VGT HardRed:** Automated Linux host hardening & posture auditing (`hardred-compliance`).

## 6. ClamAV Testfiles (`clamav-testfiles`)
- **Upstream Project:** https://www.clamav.net/ (Ubuntu `noble-updates/universe` package `clamav-testfiles` `1.5.4+dfsg-0ubuntu0.24.04.1`)
- **License:** GPL-2.0 (with OpenSSL exception, DFSG package)
- **Archive SHA-256:** `b5c8dda7925499d66d80f9548f2b0e78e0bb52dea41669c2503ffa768dc7db14`
- **Role in VGT HardRed:** Non-destructive archive and signature test samples (`hardred-malware`).
