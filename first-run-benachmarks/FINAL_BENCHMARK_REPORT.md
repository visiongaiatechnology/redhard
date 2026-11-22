# VGT HardRed Test — Gesamtbericht, Ranking & Gewinner

**Erstellt (UTC):** 2026-11-22T08:58:34.994963+00:00  
**Methodik:** VGT HardRed Test (4-Achsen-Modell: Efficacy 45% · FP-Resilienz 20% · TTFA/Schadensbegrenzung 20% · Overhead 15%; strikte Trennung Detection vs. Prevention TPR/FPR)  

## Gesamtsieger: **GeDefense Linux 6.2.0 (Max-Hardness)** (86.16 / 100 · Gate `PASS`)

## 1. Gesamt-Ranking & 4-Achsen-Matrix

| Rang | Sicherheitssystem | Gesamt (0-100) | Achse 1: Effektivität | Achse 2: FP-Resilienz | Achse 3: Latenz & Eindämmung | Achse 4: System-Overhead | Gate |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.2.0 (Max-Hardness)** (`03d-gedefense-6.2.0-max-bench`) | **86.16** | 80.49 | 100.00 | 78.07 | 95.53 | `PASS` |
| 2 | **Wazuh (Max Rules + FIM + Auditd + Active Response)** (`05-wazuh-max`) | **46.29** | 31.74 | 69.23 | 22.14 | 91.53 | `CONDITIONAL` |
| 3 | **CrowdSec (Max Collections + Bouncers + AppSec WAF)** (`04-crowdsec-max`) | **35.83** | 42.89 | 0.00 | 28.38 | 72.37 | `FAIL` |
| Ref | **Baseline (Clean Ubuntu HWE 7.0 WebStack)** (`01b-target-webstack-hwe7`) | **45.82** | 16.94 | 100.00 | 15.97 | 100.00 | `CONDITIONAL` |

## 2. Domänen-Vergleich (Detection TPR vs. Prevention TPR · FPR · TTFA)

| System | Domäne | Det TPR | Prev TPR | Det FPR | Prot FPR | Context (0-3) | Median TTFA (ms) | Damage Ratio | Score |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gedefense | `hardred-waf` | 100.0% | 100.0% | 0.0% | 0.0% | 3.00 | 250.0 | — | **100.0** |
| gedefense | `hardred-netids` | 100.0% | 100.0% | 0.0% | 0.0% | 2.50 | 175.9 | — | **98.3** |
| gedefense | `hardred-endpoint` | 53.3% | 53.3% | 0.0% | 0.0% | 2.11 | 250.0 | 18.1% | **59.0** |
| gedefense | `hardred-malware` | 100.0% | 33.3% | 0.0% | 0.0% | 1.67 | 250.0 | — | **65.6** |
| gedefense | `hardred-compliance` | 100.0% | 86.0% | 0.0% | 0.0% | 3.00 | — | — | **86.0** |
| wazuh | `hardred-waf` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| wazuh | `hardred-netids` | 25.0% | 25.0% | 0.0% | 0.0% | 2.00 | 2077.7 | — | **34.8** |
| wazuh | `hardred-endpoint` | 53.3% | 6.7% | 50.0% | 0.0% | 1.89 | 1254.9 | 100.0% | **33.5** |
| wazuh | `hardred-malware` | 66.7% | 0.0% | 100.0% | 0.0% | 2.00 | 769.5 | — | **31.7** |
| wazuh | `hardred-compliance` | 100.0% | 80.0% | 0.0% | 0.0% | 3.00 | — | — | **80.0** |
| crowdsec | `hardred-waf` | 92.9% | 85.7% | 12.5% | 12.5% | 2.00 | 584.2 | — | **86.6** |
| crowdsec | `hardred-netids` | 25.0% | 25.0% | 50.0% | 50.0% | 1.00 | 4747.2 | — | **29.6** |
| crowdsec | `hardred-endpoint` | 0.0% | 6.7% | 0.0% | 0.0% | 1.00 | 457.8 | 100.0% | **14.3** |
| crowdsec | `hardred-malware` | 0.0% | 33.3% | 0.0% | 0.0% | 0.00 | — | — | **25.0** |
| crowdsec | `hardred-compliance` | 100.0% | 78.0% | 0.0% | 0.0% | 2.00 | — | — | **78.0** |
| baseline | `hardred-waf` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-netids` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-endpoint` | 0.0% | 6.7% | 0.0% | 0.0% | 1.00 | 916.2 | 100.0% | **14.3** |
| baseline | `hardred-malware` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-compliance` | 100.0% | 78.0% | 0.0% | 0.0% | 2.00 | — | — | **78.0** |

## 3. System-Overhead, Durchsatz & Compliance-Posture

| System | HTTP RPS | HTTP p50 (ms) | HTTP p95 (ms) | HTTP p99 (ms) | Sysbench EPS | FIO IOPS | Security RSS (MiB) | Security CPU (%) | Lynis Index | Aktive LSMs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| gedefense | 730.7 | 8.74 | 17.99 | 21.53 | 90420.3 | 245.2 | 83.3 | 4.3% | 71 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| wazuh | 852.1 | 8.59 | 11.56 | 15.23 | 71832.8 | 236.4 | 71.4 | 13.4% | 65 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| crowdsec | 298.6 | 23.45 | 34.43 | 38.40 | 91298.5 | 227.6 | 302.4 | 9.2% | 63 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| baseline | 842.3 | 6.25 | 21.23 | 23.40 | 92272.2 | 258.1 | 24.8 | 0.0% | 63 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |

## 4. Gate-Bewertungen & Begründungen

- **GeDefense Linux 6.2.0 (Max-Hardness)** (`PASS`): All AMTSO/WCP false-positive gates passed
- **Wazuh (Max Rules + FIM + Auditd + Active Response)** (`CONDITIONAL`): Detection FPR elevated (EP=50.0%, WAF=0.0%)
- **CrowdSec (Max Collections + Bouncers + AppSec WAF)** (`FAIL`): WAF Protection FPR 12.50% > 1% gate; Detection FPR elevated (EP=0.0%, WAF=12.5%)
- **Baseline (Clean Ubuntu HWE 7.0 WebStack)** (`CONDITIONAL`): Unprotected baseline control target

## 5. Einzeltest-Matrix (Ground Truth vs. Ist-Ergebnis)

| System | Case-ID | Domäne | Polarität | MITRE | Detected | Prevented | Context | TTFA (ms) | Damage | Evidenz |
|---|---|---|---|---|---|---|---|---:|---|---|
| gedefense | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| gedefense | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| gedefense | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| gedefense | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | NO | 1/3 | 94.0 | — | `disk=STILL_PRESENT; malware.execution_blocked` |
| gedefense | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 1/3 | 3414.7 | — | `nested=WROTE 808; malware.execution_blocked` |
| gedefense | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| gedefense | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| gedefense | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | YES | YES | 3/3 | 250.0 | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": false, "errno": "EPER` |
| gedefense | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | YES | YES | 3/3 | 250.0 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| gedefense | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | YES | 3/3 | 250.0 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| gedefense | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 287.7 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": false, "errno": ` |
| gedefense | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | YES | YES | 1/3 | 911.5 | 23/120 | `rc=4294967295, out={}; xdr.XDR.RANSOM_ENTROPY_BURST` |
| gedefense | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | YES | YES | 1/3 | 17.1 | 50/600 | `rc=4294967295, out={}; xdr.XDR.RANSOM_RENAME_STORM` |
| gedefense | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | YES | YES | 1/3 | 607.1 | 16/60 | `rc=4294967295, out={}; xdr.XDR.RANSOM_ENTROPY_BURST` |
| gedefense | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | YES | YES | 3/3 | 250.0 | — | `rc=28, out={}; STYX.POLICY_DROP` |
| gedefense | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | YES | NO | 3/3 | 250.0 | — | `rc=0, out={}; STYX.POLICY_DROP` |
| gedefense | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| gedefense | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; xdr.kinetic_block, kinetic.block_applied, kinetic_strike, l7.block, L7` |
| gedefense | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 250.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 3/3 | 17.0 | — | `blocked_or_dropped=10/25; xdr.egress_blocked, xdr.egress_blocked, xdr.kinetic_block, kinet` |
| gedefense | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 3/3 | 334.7 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| gedefense | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | YES | YES | 3/3 | 6.4 | — | `blocked_or_dropped=199/240; kinetic.block_applied, kinetic_strike, xdr.egress_blocked, xdr` |
| gedefense | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | YES | YES | 1/3 | 3664.8 | — | `post_scan_banned=True, open_blocked=False; kinetic.block_applied, kinetic_strike, kinetic.` |
| wazuh | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| wazuh | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| wazuh | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | YES | NO | 2/3 | 625.0 | — | `rc=0; 554:File added to the system.` |
| wazuh | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | NO | 2/3 | 831.0 | — | `disk=STILL_PRESENT; 554:File added to the system.` |
| wazuh | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 2/3 | 708.0 | — | `nested=WROTE 814; 554:File added to the system.` |
| wazuh | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | YES | NO | 2/3 | 1089.1 | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; 554:File added to the system., 554:F` |
| wazuh | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| wazuh | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| wazuh | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | YES | NO | 2/3 | 1254.9 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| wazuh | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | NO | 2/3 | 1627.0 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| wazuh | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 1461.4 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| wazuh | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | YES | NO | 2/3 | 1093.6 | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| wazuh | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | YES | NO | 2/3 | 1368.7 | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| wazuh | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | YES | NO | 2/3 | 2305.3 | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| wazuh | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | YES | NO | 2/3 | 799.7 | — | `rc=0, out={}; 554:File added to the system., 554:File added to the system., 554:File added` |
| wazuh | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | YES | NO | 2/3 | 194.6 | — | `rc=0, out={}; 554:File added to the system., 554:File added to the system., 554:File added` |
| wazuh | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | YES | NO | 2/3 | 918.5 | — | `rc=0, out={}; 554:File added to the system., 554:File added to the system., 554:File added` |
| wazuh | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; none` |
| wazuh | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 2/3 | 2077.7 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| wazuh | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/240; none` |
| wazuh | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; none` |
| crowdsec | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | YES | YES | 2/3 | 460.0 | — | `http=403; anomaly score block: sql_injection: 10, anomaly: 13, ` |
| crowdsec | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | YES | NO | 2/3 | 1921.5 | — | `ok=6/6 blocked=0; crowdsecurity/crowdsec-appsec-outofband, crowdsecurity/crowdsec-appsec-o` |
| crowdsec | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | YES | 0/3 | — | — | `tls_ok=0/4 blocked=4; none` |
| crowdsec | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| crowdsec | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | NO | NO | 0/3 | — | — | `disk=STILL_PRESENT; none` |
| crowdsec | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | YES | 0/3 | — | — | `http=None; none` |
| crowdsec | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | NO | NO | 0/3 | — | — | `nested=WROTE 818; none` |
| crowdsec | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| crowdsec | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| crowdsec | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| crowdsec | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| crowdsec | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| crowdsec | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 457.8 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| crowdsec | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| crowdsec | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| crowdsec | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| crowdsec | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 3369.3 | — | `http=403; anomaly score block: sql_injection: 50, anomaly: 53, ` |
| crowdsec | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 463.7 | — | `http=403; anomaly score block: sql_injection: 10, anomaly: 13, ` |
| crowdsec | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 108.5 | — | `http=403; anomaly score block: sql_injection: 5, anomaly: 8, ` |
| crowdsec | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 659.2 | — | `http=403; crowdsecurity/appsec-native, anomaly score block: xss: 50, anomaly: 53, , crowds` |
| crowdsec | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 625.6 | — | `http=403; anomaly score block: xss: 20, anomaly: 23, ` |
| crowdsec | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 1194.1 | — | `http=403; anomaly score block: lfi: 40, rce: 10, anomaly: 53, ` |
| crowdsec | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 426.4 | — | `http=403; anomaly score block: lfi: 35, anomaly: 38, ` |
| crowdsec | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 2/3 | 330.8 | — | `http=403; anomaly score block: lfi: 10, rce: 20, anomaly: 33, ` |
| crowdsec | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 2/3 | 313.7 | — | `http=403; anomaly score block: anomaly: 8, ` |
| crowdsec | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 128.1 | — | `http=403; anomaly score block: rce: 10, anomaly: 13, ` |
| crowdsec | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 2/3 | 687.9 | — | `http=403; anomaly score block: rfi: 10, rce: 10, anomaly: 23, ` |
| crowdsec | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | YES | YES | 2/3 | 644.2 | — | `http=403; anomaly score block: lfi: 5, anomaly: 13, ` |
| crowdsec | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | NO | 2/3 | 584.2 | — | `http=200; anomaly score block: anomaly: 8, ` |
| crowdsec | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; none` |
| crowdsec | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | NO | 2/3 | 165.4 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| crowdsec | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | YES | 0/3 | 9329.1 | — | `blocked_or_dropped=56/240; none` |
| crowdsec | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; none` |
| baseline | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=12/12 blocked=0; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=6/6 blocked=0; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | NO | NO | 0/3 | — | — | `disk=STILL_PRESENT; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | NO | NO | 0/3 | — | — | `nested=WROTE 808; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; baseline unprotected webstack (no se` |
| baseline | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| baseline | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| baseline | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| baseline | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 916.2 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| baseline | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| baseline | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| baseline | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| baseline | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| baseline | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/240; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; baseline unprotected webstack (no security dae` |
