"""CrowdSec LAPI, Bouncer & AppSec WAF telemetry adapter."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from vgt_hardred.adapters.base import AdapterCursor, TelemetryVerdict, compute_context_maturity, parse_iso_utc
from vgt_hardred.errors import TransportError
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController

_REMOTE_CS_SNAPSHOT_PY = r'''
import json, subprocess

def run_json(cmd):
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=12)
        return json.loads(out) if out.strip() else []
    except Exception:
        return []

alerts = run_json(["sudo", "cscli", "alerts", "list", "-l", "100", "-o", "json"])
decisions = run_json(["sudo", "cscli", "decisions", "list", "-o", "json"])
appsec_lines = 0
for p in ("/var/log/nginx/error.log", "/var/log/crowdsec.log"):
    try:
        txt = subprocess.check_output(["sudo", "tail", "-n", "400", p], text=True, stderr=subprocess.DEVNULL, timeout=5)
        for ln in txt.splitlines():
            low = ln.lower()
            if "appsec" in low or "banned" in low or " 403 " in low:
                appsec_lines += 1
    except Exception:
        pass

print(json.dumps({
    "alerts": alerts if isinstance(alerts, list) else [],
    "decisions": decisions if isinstance(decisions, list) else [],
    "appsec_lines": appsec_lines,
}))
'''


class CrowdSecAdapter:
    contender_id = "crowdsec"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["crowdsec", "crowdsec-firewall-bouncer", "crowdsec-nginx-bouncer", "openresty", "nginx"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()

    def clear_attacker_blocks(self) -> None:
        self.vm.ssh(
            "sudo cscli decisions delete --all 2>/dev/null || true; "
            "sudo nft flush set ip crowdsec crowdsec-blacklists 2>/dev/null || true; "
            "sudo nft flush set ip6 crowdsec crowdsec6-blacklists 2>/dev/null || true",
            timeout_sec=15,
        )

    def _fetch_snapshot(self) -> dict[str, Any]:
        for attempt in range(2):
            try:
                rc, out, _ = self.vm.ssh("python3 -", timeout_sec=30, stdin_text=_REMOTE_CS_SNAPSHOT_PY)
                if rc == 0 and out.strip():
                    return json.loads(out.strip().splitlines()[-1])
            except TransportError:
                if attempt == 0:
                    time.sleep(1.0)
                    continue
            except Exception:
                break
        return {"alerts": [], "decisions": [], "appsec_lines": 0}

    def capture_cursor(self) -> AdapterCursor:
        snap = self._fetch_snapshot()
        return AdapterCursor(captured_utc=datetime.now(timezone.utc).isoformat(), state=snap)

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 2.0,
    ) -> TelemetryVerdict:
        if settle_sec > 0:
            time.sleep(settle_sec)
        before = cursor.state
        after = self._fetch_snapshot()
        t0_epoch = parse_iso_utc(started_utc) or 0.0

        b_alert_ids = {a.get("id") for a in (before.get("alerts") or []) if isinstance(a, dict)}
        b_dec_ids = {d.get("id") for d in (before.get("decisions") or []) if isinstance(d, dict)}

        alerts: list[dict[str, Any]] = []
        ttfa_candidates: list[float] = []

        for al in (after.get("alerts") or []):
            if not isinstance(al, dict):
                continue
            aid = al.get("id")
            ts = parse_iso_utc(al.get("created_at") or al.get("start_at"))
            if aid not in b_alert_ids or (ts and ts >= t0_epoch - 0.5):
                alerts.append({
                    "sensor": "crowdsec-lapi",
                    "rule_id": al.get("scenario") or al.get("reason") or al.get("message") or "crowdsec/alert",
                    "kind": al.get("kind", ""),
                    "src_ip": (al.get("source") or {}).get("ip", ""),
                    "events_count": al.get("events_count", 1),
                    "target": al.get("message") or al.get("reason") or "",
                })
                if ts and ts >= t0_epoch:
                    ttfa_candidates.append(max(1.0, (ts - t0_epoch) * 1000.0))

        for dec in (after.get("decisions") or []):
            if isinstance(dec, dict) and dec.get("id") not in b_dec_ids:
                alerts.append({
                    "sensor": "crowdsec-bouncer",
                    "rule_id": dec.get("scenario", "crowdsec/decision"),
                    "src_ip": dec.get("value", ""),
                    "type": dec.get("type", "ban"),
                })

        appsec_delta = int(after.get("appsec_lines", 0)) - int(before.get("appsec_lines", 0))
        if appsec_delta > 0 and not alerts:
            alerts.append({"sensor": "crowdsec-appsec", "rule_id": "crowdsec/appsec-waf", "delta": appsec_delta})

        detected = len(alerts) > 0
        ctx = compute_context_maturity(alerts, has_lineage_or_chain=False)
        ttfa = round(min(ttfa_candidates), 2) if ttfa_candidates else (500.0 if detected else None)
        summary = ", ".join(str(a.get("rule_id")) for a in alerts[:5]) or "none"
        return TelemetryVerdict(
            detected=detected,
            context_maturity=ctx,
            ttfa_ms=ttfa,
            evidence_summary=summary,
            raw_alerts=alerts[:15],
        )
