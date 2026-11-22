"""Endpoint & kernel behavioral domain runner (Atomic Red Team + Falco event-generator + hardred-probe)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vgt_hardred.adapters.base import ContenderAdapter
from vgt_hardred.models import CaseResult, GroundTruthCase
from vgt_hardred.vm_control import VMController


def run_endpoint_domain(
    vm: VMController,
    adapter: ContenderAdapter,
    probe_linux_bin: Path,
    event_gen_linux_bin: Path | None,
    atomic_dir: Path | None,
) -> tuple[list[CaseResult], dict[str, Any]]:
    cases_out: list[CaseResult] = []
    meta: dict[str, Any] = {}
    vm.ensure_sandboxes()

    staged_probe = f"{vm.cfg.remote_work_dir}/hardred-probe"
    vm.scp_push(probe_linux_bin, staged_probe, timeout_sec=60)
    # Install test drivers into root-owned /usr/local/bin so W^X / /tmp-noexec
    # protections (e.g. TITAN-Exec untrusted) keep blocking /tmp/hardred-sandbox
    # payloads without blocking the benchmark instrumentation binary itself.
    rc_inst, _, _ = vm.ssh(
        f"sudo install -m 0755 -o root -g root {staged_probe} /usr/local/bin/hardred-probe && rm -f {staged_probe}",
        timeout_sec=15,
    )
    if rc_inst == 0:
        remote_probe = "/usr/local/bin/hardred-probe"
    else:
        remote_probe = staged_probe
        vm.ssh(f"chmod +x {remote_probe}", timeout_sec=15)

    remote_evgen = ""
    if event_gen_linux_bin and event_gen_linux_bin.is_file():
        staged_evgen = f"{vm.cfg.remote_work_dir}/event-generator"
        vm.scp_push(event_gen_linux_bin, staged_evgen, timeout_sec=60)
        rc_ev_inst, _, _ = vm.ssh(
            f"sudo install -m 0755 -o root -g root {staged_evgen} /usr/local/bin/event-generator && rm -f {staged_evgen}",
            timeout_sec=15,
        )
        if rc_ev_inst == 0:
            remote_evgen = "/usr/local/bin/event-generator"
        else:
            remote_evgen = staged_evgen
            vm.ssh(f"chmod +x {remote_evgen}", timeout_sec=15)
        meta["event_generator_pushed"] = True

    def exec_probe_case(
        case: GroundTruthCase,
        cmd: str,
        timeout_sec: int = 45,
        progress_file: str | None = None,
        total_files: int | None = None,
        prevented_check: str = "nonzero_exit_or_kill",
        settle_sec: float = 1.5,
    ) -> CaseResult:
        cursor = adapter.capture_cursor()
        t0_utc = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()
        rc, out, err = vm.ssh(cmd, timeout_sec=timeout_sec)
        dur = (time.perf_counter() - t0) * 1000.0
        end_utc = datetime.now(timezone.utc).isoformat()

        damaged: int | None = None
        parsed_json: dict[str, Any] = {}
        try:
            s_idx = out.find("{")
            e_idx = out.rfind("}")
            if s_idx != -1 and e_idx > s_idx:
                parsed_json = json.loads(out[s_idx : e_idx + 1])
        except Exception:
            parsed_json = {}

        if progress_file:
            _, p_out, _ = vm.ssh(f"cat {progress_file} 2>/dev/null || true", timeout_sec=10)
            p_lines = [ln.strip() for ln in p_out.splitlines() if ln.strip()]
            if p_lines:
                try:
                    last_obj = json.loads(p_lines[-1])
                    if "completed" in last_obj:
                        damaged = int(last_obj["completed"])
                    else:
                        damaged = len(p_lines)
                except Exception:
                    damaged = len(p_lines)
            else:
                damaged = 0
            if total_files is not None and damaged is not None:
                damaged = min(total_files, damaged)

        verdict = adapter.collect_since(cursor, case, t0_utc, settle_sec=settle_sec)

        prevented = False
        if prevented_check == "nonzero_exit_or_kill":
            prevented = rc != 0 or parsed_json.get("ok") is False
        elif prevented_check == "ransom_stop":
            # Signal killed (137/143/etc. or SSH -1 -> 255/4294967295), halted early (< total_files), or child killed.
            killed_sig = rc in (137, 143, 129, 139, 255, 4294967295) or bool(parsed_json.get("child_killed"))
            early_stop = (damaged is not None and total_files is not None and damaged < total_files)
            prevented = killed_sig or early_stop or rc != 0
        elif prevented_check == "lpe_sctp_blocked":
            sctp_ok = (parsed_json.get("sctp_socket") or {}).get("ok")
            dccp_ok = (parsed_json.get("dccp_socket") or {}).get("ok")
            prevented = (sctp_ok is False) or (dccp_ok is False)
        elif prevented_check == "benign_ok":
            prevented = rc != 0 or parsed_json.get("ok") is False

        ttfa = verdict.ttfa_ms
        if ttfa is None and prevented and case.polarity == "attack":
            ttfa = round(dur, 2)

        return CaseResult(
            case=case,
            started_utc=t0_utc,
            ended_utc=end_utc,
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=prevented,
            context_maturity=verdict.context_maturity if verdict.detected else (1 if prevented and case.polarity == "attack" else 0),
            ttfa_ms=ttfa,
            pre_kill_damage=damaged,
            pre_kill_total=total_files,
            exit_code=rc,
            evidence_summary=f"rc={rc}, out={json.dumps(parsed_json)[:140] or out.strip()[:100]}; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
            error=err.strip()[:200] if err and rc != 0 else "",
        )

    # 1. Benign Admin Workload FIRST (0% Protection FPR Gate — uses trusted system binaries)
    benign_py = (
        f"import hashlib, json, os, subprocess, tarfile\n"
        f"sb = '{vm.cfg.sandbox_root}/benign1'\n"
        f"os.makedirs(sb, exist_ok=True)\n"
        f"dpkg = subprocess.run(['dpkg-query', '-W', '-f=${{Version}}', 'bash'], capture_output=True, text=True)\n"
        f"osrel = open('/etc/os-release').read(128)\n"
        f"p1 = os.path.join(sb, 'note.txt'); open(p1, 'w').write('VGT HardRed Benign Backup\\n' * 10)\n"
        f"with tarfile.open(os.path.join(sb, 'backup.tar.gz'), 'w:gz') as tf: tf.add(p1, arcname='note.txt')\n"
        f"digest = hashlib.sha256(open(p1, 'rb').read()).hexdigest()\n"
        f"print(json.dumps({{'ok': dpkg.returncode == 0 and len(osrel) > 10, 'sha256': digest[:16]}}))\n"
    )
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-BENIGN-01",
                domain="hardred-endpoint",
                category="Benign Admin Workload",
                title="Trusted dpkg-query, tar backup, os-release read, SHA-256 hash",
                polarity="benign",
                mitre_technique="NONE",
                mitre_tactic="None",
                tool_source="system-admin",
                expected_prevention=False,
                severity="info",
            ),
            f"python3 - <<'PY'\n{benign_py}PY",
            prevented_check="benign_ok",
            settle_sec=0.4,
        )
    )
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-BENIGN-02",
                domain="hardred-endpoint",
                category="Benign Admin Process Tree",
                title="Normal bash+python3 pipeline listing /etc/nginx configuration",
                polarity="benign",
                mitre_technique="NONE",
                mitre_tactic="None",
                tool_source="bash",
                expected_prevention=False,
                severity="info",
            ),
            "python3 -c \"import os, json; print(json.dumps({'ok': os.path.isdir('/etc/nginx')}))\"",
            prevented_check="benign_ok",
            settle_sec=0.4,
        )
    )

    # 2. Fileless memfd_create execution (T1620)
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-FILELESS-MEMFD-01",
                domain="hardred-endpoint",
                category="Fileless Execution (memfd_create)",
                title="In-memory ELF/script execution via memfd_create (/proc/self/fd)",
                polarity="attack",
                mitre_technique="T1620",
                mitre_tactic="Defense Evasion",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="critical",
            ),
            f"{remote_probe} memfd-exec",
            settle_sec=0.6,
        )
    )

    # 3. /dev/shm Dropper Execution (T1059.004)
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-SHM-EXEC-01",
                domain="hardred-endpoint",
                category="/dev/shm Dropper Execution",
                title="Executable script staged & executed from /dev/shm/hardred-sandbox",
                polarity="attack",
                mitre_technique="T1059.004",
                mitre_tactic="Execution",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="high",
            ),
            f"{remote_probe} shm-exec -sandbox {vm.cfg.shm_sandbox_root}",
            settle_sec=0.6,
        )
    )

    # 4. Untrusted ELF in /tmp execution -> directly tests TITAN-Exec BPF-LSM (T1204.002)
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-TMP-ELF-01",
                domain="hardred-endpoint",
                category="Untrusted Binary Execution (/tmp)",
                title="Unverified ELF binary copied to /tmp and executed (TITAN-Exec gate)",
                polarity="attack",
                mitre_technique="T1204.002",
                mitre_tactic="Execution",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="critical",
            ),
            f"{remote_probe} tmp-exec -sandbox {vm.cfg.sandbox_root}/tmpexec",
            settle_sec=0.6,
        )
    )

    # 5. Kernel LPE & Raw Socket / Ptrace Probes (T1068 / T1055.008)
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-LPE-KERNEL-01",
                domain="hardred-endpoint",
                category="Kernel LPE & Protocol Attack Surface",
                title="Blacklisted SCTP/DCCP socket + AF_PACKET + ptrace + /etc/shadow probe",
                polarity="attack",
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="high",
            ),
            f"{remote_probe} lpe-probe",
            prevented_check="lpe_sctp_blocked",
            settle_sec=0.6,
        )
    )

    # 6. AES-256 Ransomware Burst (120 files, 4KB each -> high entropy jump)
    aes_prog = f"{vm.cfg.sandbox_root}/aes_progress.jsonl"
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-RANSOM-AES-01",
                domain="hardred-endpoint",
                category="Ransomware AES-256 Encryption Burst",
                title="In-place AES-256-GCM encryption of 120 realistic files (TTFA + pre-kill damage)",
                polarity="attack",
                mitre_technique="T1486",
                mitre_tactic="Impact",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="critical",
            ),
            f"rm -f {aes_prog} && {remote_probe} aes-ransom -sandbox {vm.cfg.sandbox_root}/aes -count 120 -delay-ms 15 -progress {aes_prog}",
            timeout_sec=60,
            progress_file=aes_prog,
            total_files=120,
            prevented_check="ransom_stop",
            settle_sec=2.5,
        )
    )

    # 7. Rapid Rename / Delete Storm (600 files in 50-file batches)
    storm_prog = f"{vm.cfg.sandbox_root}/storm_progress.jsonl"
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-RANSOM-STORM-01",
                domain="hardred-endpoint",
                category="Ransomware Rename/Wiper Storm",
                title="600-file / 50-batch rapid rename+wipe storm (TTFA + pre-kill damage)",
                polarity="attack",
                mitre_technique="T1485",
                mitre_tactic="Impact",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="critical",
            ),
            f"rm -f {storm_prog} && {remote_probe} rename-storm -sandbox {vm.cfg.sandbox_root}/storm -count 600 -batch 50 -delay-ms 5 -progress {storm_prog}",
            timeout_sec=60,
            progress_file=storm_prog,
            total_files=600,
            prevented_check="ransom_stop",
            settle_sec=2.5,
        )
    )

    # 8. Child-Process Lineage & Kill Resilience
    child_prog = f"{vm.cfg.sandbox_root}/child_progress.jsonl"
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-LINEAGE-CHILD-01",
                domain="hardred-endpoint",
                category="Process Lineage / Child-Kill Resilience",
                title="Parent spawns child conducting AES-256 burst (child vs tree kill check)",
                polarity="attack",
                mitre_technique="T1059",
                mitre_tactic="Execution",
                tool_source="hardred-probe",
                expected_prevention=True,
                severity="high",
            ),
            f"rm -f {child_prog} && {remote_probe} child-kill-test -sandbox {vm.cfg.sandbox_root}/child -count 60 -delay-ms 20 -progress {child_prog}",
            timeout_sec=60,
            progress_file=child_prog,
            total_files=60,
            prevented_check="ransom_stop",
            settle_sec=2.5,
        )
    )

    # 9. StyX / Cgroup C2 Egress Containment (run inside exact php8.3-fpm.service cgroup)
    styx_cmd = (
        "sudo bash -c '"
        "PID=$(pgrep -o php-fpm8.3 || true); "
        "if [ -n \"$PID\" ]; then "
        "CG=$(awk -F: \"{print \\$3}\" /proc/$PID/cgroup | head -n1); "
        "echo $$ > \"/sys/fs/cgroup${CG}/cgroup.procs\" 2>/dev/null || true; "
        "fi; "
        "exec curl -s -o /dev/null --max-time 3 http://1.1.1.1/'"
    )
    cases_out.append(
        exec_probe_case(
            GroundTruthCase(
                case_id="EP-C2-EGRESS-01",
                domain="hardred-endpoint",
                category="Unauthorized C2 Egress (Web Worker Cell)",
                title="Outbound HTTP egress to 1.1.1.1 from inside php8.3-fpm.service cgroup",
                polarity="attack",
                mitre_technique="T1071.001",
                mitre_tactic="Command and Control",
                tool_source="styx-cgroup-curl",
                expected_prevention=True,
                severity="high",
            ),
            styx_cmd,
            timeout_sec=15,
            prevented_check="nonzero_exit_or_kill",
            settle_sec=2.2,
        )
    )

    # 10. Falco Event-Generator Real Kernel Syscall Pack
    if remote_evgen:
        ev_actions = [
            ("EP-FALCO-01", "^syscall\\.ReadSensitiveFileUntrusted$", "T1003.008", "Credential Access", "Read /etc/shadow by untrusted program"),
            ("EP-FALCO-02", "^syscall\\.CreateSymlinkOverSensitiveFiles$", "T1036", "Defense Evasion", "Symlink over sensitive /etc target"),
            ("EP-FALCO-03", "^syscall\\.PtraceAntiDebugAttempt$", "T1055.008", "Privilege Escalation", "Ptrace process memory / anti-debug syscall"),
        ]
        for cid, action_regex, tech, tactic, title in ev_actions:
            cases_out.append(
                exec_probe_case(
                    GroundTruthCase(
                        case_id=cid,
                        domain="hardred-endpoint",
                        category="Kernel Syscall Behavior (Falco)",
                        title=title,
                        polarity="attack",
                        mitre_technique=tech,
                        mitre_tactic=tactic,
                        tool_source="falco-event-generator",
                        expected_prevention=False,
                        severity="high",
                    ),
                    f"{remote_evgen} run { _sq(action_regex) } || true",
                    timeout_sec=25,
                    prevented_check="nonzero_exit_or_kill",
                    settle_sec=1.8,
                )
            )

    # 11. Atomic Red Team Curated Non-Destructive Linux TTPs
    if atomic_dir and atomic_dir.is_dir():
        meta["atomic_dir_present"] = True
        art_cases = [
            ("EP-ART-T1087", "T1087.001", "Discovery", "Local Account Enumeration (/etc/passwd, id, lastlog)", "id && getent passwd | head -n 10 && sudo -n true 2>&1 || true"),
            ("EP-ART-T1059", "T1059.004", "Execution", "Base64 Obfuscated Shell Execution", "echo 'dW5hbWUgLWE7IGlk' | base64 -d | sh"),
            ("EP-ART-T1053", "T1053.003", "Persistence", "Cron Persistence Staging & Cleanup", f"(crontab -l 2>/dev/null; echo '# hardred-t1053-test') | crontab - && crontab -l | grep -v hardred-t1053-test | crontab - || true"),
            ("EP-ART-T1548", "T1548.001", "Privilege Escalation", "SUID/Capabilities Enumeration", "find /usr/bin -perm -4000 2>/dev/null | head -n 20"),
        ]
        for cid, tech, tactic, title, shell_cmd in art_cases:
            # Verify official atomic yaml exists in cloned repo for strict provenance
            yaml_exists = (atomic_dir / tech / f"{tech}.yaml").is_file()
            cases_out.append(
                exec_probe_case(
                    GroundTruthCase(
                        case_id=cid,
                        domain="hardred-endpoint",
                        category="Atomic Red Team Linux TTP",
                        title=f"{title} [yaml={yaml_exists}]",
                        polarity="attack",
                        mitre_technique=tech,
                        mitre_tactic=tactic,
                        tool_source="atomic-red-team",
                        expected_prevention=False,
                        severity="medium",
                    ),
                    f"bash -c { _sq(shell_cmd) }",
                    timeout_sec=20,
                    prevented_check="nonzero_exit_or_kill",
                    settle_sec=1.8,
                )
            )

    return cases_out, meta


def _sq(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"
