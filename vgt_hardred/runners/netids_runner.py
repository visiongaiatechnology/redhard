"""Network IDS, Velocity Rate-Limit, Portscan & Brute-Force runner."""

from __future__ import annotations

import http.client
import json
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vgt_hardred.adapters.base import ContenderAdapter
from vgt_hardred.models import CaseResult, GroundTruthCase
from vgt_hardred.vm_control import VMController


def run_netids_benign(
    vm: VMController,
    adapter: ContenderAdapter,
) -> list[CaseResult]:
    cases_out: list[CaseResult] = []
    base_url = vm.cfg.http_base_url
    https_url = vm.cfg.https_base_url

    # 1. Benign paced network traffic FIRST (6 requests @ 250ms)
    benign_case = GroundTruthCase(
        case_id="NET-BENIGN-01",
        domain="hardred-netids",
        category="Benign Paced Web Traffic",
        title="Legitimate paced HTTP traffic (6 req @ 250ms)",
        polarity="benign",
        mitre_technique="NONE",
        mitre_tactic="None",
        tool_source="hardred-netbench",
        expected_prevention=False,
        severity="info",
    )
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    ok_cnt, blk_cnt = 0, 0
    parsed_u = urllib.parse.urlparse(base_url)
    conn = http.client.HTTPConnection(parsed_u.hostname or vm.cfg.target_ip, parsed_u.port or 80, timeout=3.0)
    try:
        for _ in range(6):
            try:
                conn.request("GET", "/health.php", headers={"Connection": "keep-alive"})
                resp = conn.getresponse()
                _ = resp.read()
                if resp.status == 200:
                    ok_cnt += 1
                else:
                    blk_cnt += 1
            except Exception:
                blk_cnt += 1
            time.sleep(0.25)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, benign_case, t0_utc, settle_sec=1.0)
    cases_out.append(
        CaseResult(
            case=benign_case,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=(blk_cnt > 0),
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms,
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"ok={ok_cnt}/6 blocked={blk_cnt}; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )

    # 2. Benign HTTPS TLS normal handshakes (4 handshakes)
    benign_tls = GroundTruthCase(
        case_id="NET-BENIGN-02",
        domain="hardred-netids",
        category="Benign TLS Connections",
        title="Normal TLS 1.3 HTTPS requests (4 handshakes)",
        polarity="benign",
        mitre_technique="NONE",
        mitre_tactic="None",
        tool_source="urllib-tls",
        expected_prevention=False,
        severity="info",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    tls_ok, tls_blk = 0, 0
    for _ in range(4):
        try:
            with urllib.request.urlopen(f"{https_url}/health.php", timeout=3, context=ctx) as r:
                if r.status == 200:
                    tls_ok += 1
        except Exception:
            tls_blk += 1
        time.sleep(0.2)
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, benign_tls, t0_utc, settle_sec=1.0)
    cases_out.append(
        CaseResult(
            case=benign_tls,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=(tls_blk > 0),
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms,
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"tls_ok={tls_ok}/4 blocked={tls_blk}; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )
    return cases_out


def run_netids_attacks(
    vm: VMController,
    adapter: ContenderAdapter,
    netbench_bin: Path,
) -> tuple[list[CaseResult], dict[str, Any]]:
    cases_out: list[CaseResult] = []
    target_ip = vm.cfg.target_ip
    base_url = vm.cfg.http_base_url
    meta: dict[str, Any] = {}

    # 3. HTTP Login Brute-Force (/wp-login.php simulation)
    adapter.clear_attacker_blocks()
    http_bf_case = GroundTruthCase(
        case_id="NET-BRUTE-HTTP-01",
        domain="hardred-netids",
        category="HTTP Auth Brute-Force",
        title="Rapid HTTP credential spraying (/wp-login.php 25x)",
        polarity="attack",
        mitre_technique="T1110.001",
        mitre_tactic="Credential Access",
        tool_source="hardred-netprobe",
        expected_prevention=True,
        severity="high",
    )
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    bf_blocked = 0
    for idx in range(25):
        req = urllib.request.Request(
            f"{base_url}/wp-login.php",
            data=f"log=admin&pwd=wrongpass_{idx}".encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2.5) as r:
                if r.status in (403, 429):
                    bf_blocked += 1
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                bf_blocked += 1
        except Exception:
            bf_blocked += 1
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, http_bf_case, t0_utc, settle_sec=2.0)
    cases_out.append(
        CaseResult(
            case=http_bf_case,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=(bf_blocked > 0),
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms or (round(dur, 2) if bf_blocked > 0 else None),
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"blocked_or_dropped={bf_blocked}/25; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )

    # 4. SSH Brute-Force Spray (invalid auth attempts via hardred-netbench)
    adapter.clear_attacker_blocks()
    ssh_case = GroundTruthCase(
        case_id="NET-BRUTE-SSH-01",
        domain="hardred-netids",
        category="SSH Credential Brute-Force",
        title="SSH failed login burst (18 attempts -> IP ban test)",
        polarity="attack",
        mitre_technique="T1110.001",
        mitre_tactic="Credential Access",
        tool_source="hardred-netbench",
        expected_prevention=True,
        severity="high",
    )
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    ssh_res = _run_netbench(netbench_bin, ["ssh-spray", "-addr", f"{target_ip}:22", "-attempts", "18", "-delay-ms", "80"])
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, ssh_case, t0_utc, settle_sec=3.0)
    ssh_prev = int(ssh_res.get("first_drop_idx", -1)) >= 0 or (
        int(ssh_res.get("timeouts", 0)) + int(ssh_res.get("tcp_refused", 0))
    ) >= 3
    cases_out.append(
        CaseResult(
            case=ssh_case,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=ssh_prev,
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms,
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"ssh_spray={ssh_res}; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )

    # 5. Velocity Burst / Flood (rate-burst via hardred-netbench)
    adapter.clear_attacker_blocks()
    burst_case = GroundTruthCase(
        case_id="NET-VELOCITY-01",
        domain="hardred-netids",
        category="HTTP/L4 Velocity Burst",
        title="High-concurrency connection & request flood (240 req @ 28 threads)",
        polarity="attack",
        mitre_technique="T1499.002",
        mitre_tactic="Impact",
        tool_source="hardred-netbench",
        expected_prevention=True,
        severity="high",
    )
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    burst_res = _run_netbench(netbench_bin, ["rate-burst", "-url", f"{base_url}/index.php?burst=1", "-requests", "240", "-concurrency", "28", "-timeout-ms", "2500"])
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, burst_case, t0_utc, settle_sec=2.0)
    blk_burst = (
        int(burst_res.get("rate_limited_429", 0))
        + int(burst_res.get("blocked_403", 0))
        + int(burst_res.get("other_4xx", 0))
        + int(burst_res.get("timeouts", 0))
        + int(burst_res.get("transport_errors", 0))
    )
    burst_prev = blk_burst >= 10
    meta["rate_burst"] = burst_res
    cases_out.append(
        CaseResult(
            case=burst_case,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=burst_prev,
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms or (round(dur, 2) if burst_prev else None),
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"blocked_or_dropped={blk_burst}/240; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )

    # 6. Multi-Port Scan (portscan via hardred-netbench) — runs LAST as it intentionally seeks XDP/firewall IP ban!
    adapter.clear_attacker_blocks()
    scan_case = GroundTruthCase(
        case_id="NET-PORTSCAN-01",
        domain="hardred-netids",
        category="Multi-Port Reconnaissance",
        title="16-port TCP connect scan -> Kinetic XDP / Firewall Ban verification",
        polarity="attack",
        mitre_technique="T1046",
        mitre_tactic="Discovery",
        tool_source="hardred-netbench",
        expected_prevention=True,
        severity="high",
    )
    cursor = adapter.capture_cursor()
    t0_utc = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    scan_res = _run_netbench(
        netbench_bin,
        ["portscan", "-host", target_ip, "-ports", "21,22,23,25,80,110,139,443,445,3306,3389,5432,6379,8080,8443,9200", "-timeout-ms", "700"],
    )
    dur = (time.perf_counter() - t0) * 1000.0
    verdict = adapter.collect_since(cursor, scan_case, t0_utc, settle_sec=2.0)
    # Follow-up probe on OPEN port 80 checks if IP is now banned/blackholed on eth1.
    ban_active = False
    try:
        urllib.request.urlopen(f"{base_url}/health.php", timeout=1.8)
    except Exception:
        ban_active = True
    open_port_blocked = any(
        r.get("port") in (22, 80, 443) and r.get("state") == "timeout"
        for r in (scan_res.get("results") or [])
        if isinstance(r, dict)
    )
    scan_prev = ban_active or open_port_blocked
    meta["portscan"] = scan_res
    meta["post_scan_ip_banned"] = ban_active
    cases_out.append(
        CaseResult(
            case=scan_case,
            started_utc=t0_utc,
            ended_utc=datetime.now(timezone.utc).isoformat(),
            duration_ms=round(dur, 2),
            detected=verdict.detected,
            prevented=scan_prev,
            context_maturity=verdict.context_maturity,
            ttfa_ms=verdict.ttfa_ms or (round(dur, 2) if scan_prev else None),
            pre_kill_damage=None,
            pre_kill_total=None,
            evidence_summary=f"post_scan_banned={ban_active}, open_blocked={open_port_blocked}; {verdict.evidence_summary}",
            raw_alerts=verdict.raw_alerts,
        )
    )

    return cases_out, meta


def _run_netbench(bin_path: Path, sub_args: list[str]) -> dict[str, Any]:
    if not bin_path.is_file():
        return {"error": f"netbench missing: {bin_path}"}
    try:
        proc = subprocess.run(
            [str(bin_path), *sub_args],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        txt = proc.stdout.strip()
        if txt:
            return json.loads(txt)
        return {"returncode": proc.returncode, "stderr": proc.stderr.strip()[:200]}
    except Exception as exc:
        return {"error": str(exc)}
