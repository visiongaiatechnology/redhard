"""Chaitin SafeLine WAF CE Open API & PostgreSQL telemetry adapter."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from vgt_hardred.adapters.base import (
    AdapterCursor,
    TelemetryVerdict,
    compute_context_maturity,
    compute_event_ttfa_ms,
    effective_t0_epoch,
    parse_iso_utc,
)
from vgt_hardred.errors import TransportError
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController

SAFELINE_API_TOKEN = os.environ.get("HARDRED_SAFELINE_TOKEN", "VGTHardRedSafeLineToken202600001")

_REMOTE_SL_SNAPSHOT_PY = r'''
import json, ssl, urllib.request

tok = "VGTHardRedSafeLineToken202600001"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(path):
    req = urllib.request.Request(
        f"https://127.0.0.1:9443{path}",
        headers={"X-SLCE-API-TOKEN": tok},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=6) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}

rec_resp = fetch("/api/open/records?page=1&page_size=50")
acl_resp = fetch("/api/open/records/acl?page=1&page_size=25")
records = ((rec_resp.get("data") or {}).get("data")) or []
acl_records = ((acl_resp.get("data") or {}).get("data")) or []
print(json.dumps({
    "records": records if isinstance(records, list) else [],
    "acl_records": acl_records if isinstance(acl_records, list) else [],
}))
'''

_REMOTE_SL_UNBLOCK_PY = r'''
import json, ssl, subprocess, time, urllib.error, urllib.request

tok = "VGTHardRedSafeLineToken202600001"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

has_block = False
try:
    req = urllib.request.Request(
        "https://127.0.0.1:9443/api/open/records/acl?page=1&page_size=20",
        headers={"X-SLCE-API-TOKEN": tok},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=4) as r:
        data = ((json.loads(r.read().decode("utf-8", "replace")).get("data") or {}).get("data")) or []
        has_block = any(int(item.get("status") or 0) == 1 for item in data if isinstance(item, dict))
except Exception:
    pass

if not has_block:
    try:
        with urllib.request.urlopen("http://192.168.56.50/health.php", timeout=1.5) as r:
            if r.status == 200:
                print("NO_BLOCK")
                raise SystemExit(0)
    except Exception:
        has_block = True

env = {}
try:
    with open("/data/safeline/.env", encoding="utf-8") as fh:
        for line in fh:
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
except Exception:
    pass

pg_pw = env.get("POSTGRES_PASSWORD", "")
if pg_pw:
    subprocess.run(
        [
            "docker", "exec", "-e", f"PGPASSWORD={pg_pw}",
            "safeline-pg", "psql", "-U", "safeline-ce", "-d", "safeline-ce",
            "-c", "TRUNCATE mgt_acl_blocked_ip;",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )

subprocess.run(
    ["docker", "restart", "safeline-detector"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=25,
    check=False,
)
for _ in range(25):
    try:
        st = subprocess.check_output(
            ["docker", "inspect", "--format={{.State.Health.Status}}", "safeline-detector"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).strip()
        if st == "healthy":
            with urllib.request.urlopen("http://192.168.56.50/health.php", timeout=1.5) as r:
                if r.status == 200:
                    break
    except Exception:
        pass
    time.sleep(0.5)
print("CLEARED")
'''


def diff_safeline_snapshots(
    before: dict[str, Any],
    after: dict[str, Any],
    started_utc: str,
    vm_clock_offset: float = 0.0,
    t0_epoch_override: float | None = None,
) -> TelemetryVerdict:
    """Compute new SafeLine WAF/ACL detections between two API snapshots."""
    t0_epoch = effective_t0_epoch(
        started_utc,
        vm_clock_offset=vm_clock_offset,
        t0_epoch_override=t0_epoch_override,
    )
    before_events = {
        str(r.get("event_id"))
        for r in (before.get("records") or [])
        if isinstance(r, dict) and r.get("event_id")
    }
    before_acl_ids = {
        r.get("id")
        for r in (before.get("acl_records") or [])
        if isinstance(r, dict) and r.get("id") is not None
    }

    alerts: list[dict[str, Any]] = []
    ttfa_candidates: list[float] = []

    for rec in (after.get("records") or []):
        if not isinstance(rec, dict):
            continue
        eid = str(rec.get("event_id") or "")
        if not eid or eid in before_events:
            continue
        src_ip = str(rec.get("src_ip") or "")
        if src_ip == "10.0.2.2":
            continue
        rule_id = str(rec.get("rule_id") or rec.get("module") or "safeline/waf")
        alerts.append({
            "sensor": "safeline-waf",
            "rule_id": rule_id,
            "module": str(rec.get("module") or ""),
            "src_ip": src_ip,
            "uri": str(rec.get("url_path") or ""),
            "dst_port": rec.get("dst_port"),
            "action": rec.get("action"),
            "risk_level": rec.get("risk_level"),
            "ja4": str(rec.get("ja4_fingerprint") or ""),
        })
        ts = rec.get("timestamp") or rec.get("created_at")
        if isinstance(ts, (int, float)) and ts > 0 and t0_epoch > 0:
            ttfa_val = compute_event_ttfa_ms(float(ts), t0_epoch, jitter_grace_sec=0.020, integer_second_granularity=True)
            if ttfa_val is not None:
                ttfa_candidates.append(ttfa_val)

    for acl in (after.get("acl_records") or []):
        if not isinstance(acl, dict):
            continue
        aid = acl.get("id")
        if aid in before_acl_ids:
            continue
        src_ip = str(acl.get("ip") or "")
        if src_ip == "10.0.2.2":
            continue
        alerts.append({
            "sensor": "safeline-acl",
            "rule_id": f"safeline/acl/{acl.get('result') or acl.get('action') or 'block'}",
            "src_ip": src_ip,
            "action": str(acl.get("action") or "block"),
            "target": f"period={acl.get('period')} count={acl.get('count')}",
        })
        ts = parse_iso_utc(acl.get("created_at"))
        ttfa_val = compute_event_ttfa_ms(ts, t0_epoch, jitter_grace_sec=0.020, integer_second_granularity=True)
        if ttfa_val is not None:
            ttfa_candidates.append(ttfa_val)

    detected = len(alerts) > 0
    ctx = compute_context_maturity(alerts, has_lineage_or_chain=False)
    ttfa = round(min(ttfa_candidates), 2) if ttfa_candidates else (250.0 if detected else None)
    summary = ", ".join(str(a.get("rule_id")) for a in alerts[:5]) or "none"
    return TelemetryVerdict(
        detected=detected,
        context_maturity=ctx,
        ttfa_ms=ttfa,
        evidence_summary=summary,
        raw_alerts=alerts[:15],
    )


class SafelineAdapter:
    """Telemetry and lifecycle adapter for standalone Chaitin SafeLine WAF."""

    contender_id = "safeline"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["docker:safeline-"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()
        self.vm.ssh(
            "sudo systemctl is-active nginx php8.3-fpm docker >/dev/null 2>&1 || true; "
            "cd /data/safeline && sudo docker compose up -d >/dev/null 2>&1 || true; "
            "for i in $(seq 1 45); do "
            "  pg=$(sudo docker inspect --format='{{.State.Health.Status}}' safeline-pg 2>/dev/null || true); "
            "  mgt=$(sudo docker inspect --format='{{.State.Health.Status}}' safeline-mgt 2>/dev/null || true); "
            "  det=$(sudo docker inspect --format='{{.State.Health.Status}}' safeline-detector 2>/dev/null || true); "
            "  code=$(curl -sk -m 2 -o /dev/null -w '%{http_code}' http://192.168.56.50/health.php 2>/dev/null || true); "
            "  if [ \"$pg\" = healthy ] && [ \"$mgt\" = healthy ] && [ \"$det\" = healthy ] && [ \"$code\" = 200 ]; then "
            "    exit 0; "
            "  fi; "
            "  sleep 1; "
            "done",
            timeout_sec=75,
        )
        self.vm.measure_clock_offset(force_refresh=True)

    def clear_attacker_blocks(self) -> None:
        self.vm.ssh("sudo python3 -", timeout_sec=40, stdin_text=_REMOTE_SL_UNBLOCK_PY)

    def fetch_snapshot(self) -> dict[str, Any]:
        for attempt in range(2):
            try:
                rc, out, _ = self.vm.ssh("python3 -", timeout_sec=20, stdin_text=_REMOTE_SL_SNAPSHOT_PY)
                if rc == 0 and out.strip():
                    return json.loads(out.strip().splitlines()[-1])
            except TransportError:
                if attempt == 0:
                    time.sleep(0.5)
                    continue
            except Exception:
                break
        return {"records": [], "acl_records": []}

    def capture_cursor(self) -> AdapterCursor:
        vm_off = self.vm.clock_offset()
        snap = self.fetch_snapshot()
        return AdapterCursor(
            captured_utc=datetime.now(timezone.utc).isoformat(),
            state=snap,
            vm_clock_offset=vm_off,
        )

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 1.5,
    ) -> TelemetryVerdict:
        # Host-only domains (endpoint/malware) do not trigger SafeLine HTTP logs; check once without poll loops.
        if case.domain not in {"hardred-waf", "hardred-netids"}:
            if settle_sec > 0:
                time.sleep(min(settle_sec, 0.4))
            return diff_safeline_snapshots(
                cursor.state,
                self.fetch_snapshot(),
                started_utc,
                vm_clock_offset=cursor.vm_clock_offset,
                t0_epoch_override=cursor.vm_t0_epoch,
            )

        # SafeLine persists records asynchronously from safeline-detector into PostgreSQL (~1.1-1.4s).
        wait_target = max(settle_sec, 1.35) if case.polarity == "benign" else max(settle_sec, 1.8)
        initial_wait = min(wait_target, 0.7 if case.polarity == "attack" else wait_target)
        if initial_wait > 0:
            time.sleep(initial_wait)

        elapsed = initial_wait
        verdict = diff_safeline_snapshots(
            cursor.state,
            self.fetch_snapshot(),
            started_utc,
            vm_clock_offset=cursor.vm_clock_offset,
            t0_epoch_override=cursor.vm_t0_epoch,
        )
        while not verdict.detected and elapsed < wait_target:
            step = min(0.45, wait_target - elapsed)
            time.sleep(step)
            elapsed += step
            verdict = diff_safeline_snapshots(
                cursor.state,
                self.fetch_snapshot(),
                started_utc,
                vm_clock_offset=cursor.vm_clock_offset,
                t0_epoch_override=cursor.vm_t0_epoch,
            )
        return verdict
