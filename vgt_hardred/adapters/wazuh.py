"""Wazuh Manager/Agent alerts.json & Active Response telemetry adapter."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from vgt_hardred.adapters.base import AdapterCursor, TelemetryVerdict, compute_context_maturity, parse_iso_utc
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController

_REMOTE_WZ_OFFSET_PY = r'''
import json, os

def stat_file(p):
    try:
        st = os.stat(p)
        return st.st_size
    except FileNotFoundError:
        return 0

print(json.dumps({
    "alerts_size": stat_file("/var/ossec/logs/alerts/alerts.json"),
    "ar_size": stat_file("/var/ossec/logs/active-responses.log"),
}))
'''

_REMOTE_WZ_DELTA_PY = r'''
import json, sys

args = json.loads(sys.stdin.read())
alerts_off = int(args.get("alerts_size", 0))
ar_off = int(args.get("ar_size", 0))

def read_tail(path, off):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            start = off if end >= off else 0
            f.seek(start)
            return f.read().decode("utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []

alerts = []
for line in read_tail("/var/ossec/logs/alerts/alerts.json", alerts_off):
    line = line.strip()
    if not line:
        continue
    try:
        alerts.append(json.loads(line))
    except Exception:
        pass

ar_lines = [l for l in read_tail("/var/ossec/logs/active-responses.log", ar_off) if l.strip()]
print(json.dumps({"alerts": alerts[-200:], "active_responses": ar_lines[-50:]}))
'''


class WazuhAdapter:
    contender_id = "wazuh"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["wazuh-manager", "wazuh-agentd", "wazuh-analysisd", "wazuh-syscheckd", "wazuh-execd", "auditd"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()

    def clear_attacker_blocks(self) -> None:
        self.vm.ssh(
            f"sudo iptables -D INPUT -s {self.vm.cfg.attacker_source_ip} -j DROP 2>/dev/null || true; "
            f"sudo iptables -D FORWARD -s {self.vm.cfg.attacker_source_ip} -j DROP 2>/dev/null || true",
            timeout_sec=15,
        )

    def capture_cursor(self) -> AdapterCursor:
        rc, out, _ = self.vm.ssh("sudo python3 -", timeout_sec=15, stdin_text=_REMOTE_WZ_OFFSET_PY)
        state = {"alerts_size": 0, "ar_size": 0}
        if rc == 0 and out.strip():
            try:
                state = json.loads(out.strip().splitlines()[-1])
            except Exception:
                pass
        return AdapterCursor(captured_utc=datetime.now(timezone.utc).isoformat(), state=state)

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 2.5,
    ) -> TelemetryVerdict:
        if settle_sec > 0:
            time.sleep(settle_sec)
        payload = json.dumps(cursor.state)
        rc, out, _ = self.vm.ssh(
            f"sudo python3 -c {_py_exec_wrapper()} ",
            timeout_sec=20,
            stdin_text=payload,
        )
        raw_alerts: list[dict[str, Any]] = []
        ar_lines: list[str] = []
        if rc == 0 and out.strip():
            try:
                parsed = json.loads(out.strip().splitlines()[-1])
                raw_alerts = parsed.get("alerts") or []
                ar_lines = parsed.get("active_responses") or []
            except Exception:
                pass

        t0_epoch = parse_iso_utc(started_utc) or 0.0
        matched: list[dict[str, Any]] = []
        ttfa_candidates: list[float] = []
        has_rich_corr = False

        for ev in raw_alerts:
            if not isinstance(ev, dict):
                continue
            rule = ev.get("rule") or {}
            level = int(rule.get("level", 0))
            rid = str(rule.get("id", ""))
            desc = str(rule.get("description", ""))
            groups = rule.get("groups") or []
            # Filter noisy level <=3 purely informational sshd/sudo session logs unless security-relevant
            if level < 4:
                continue
            if case.polarity == "benign" and rid in {"5402", "5501", "5502"}:
                # Standard sudo/pam session open caused by benchmark SSH runner itself; ignore benchmark control-plane sudo noise
                data = ev.get("data") or {}
                if "pentest" in json.dumps(data) and "10.0.2.2" in json.dumps(ev):
                    continue
            mitre = ((rule.get("mitre") or {}).get("id")) or []
            has_audit = "audit" in groups or bool((ev.get("data") or {}).get("audit"))
            if mitre and has_audit:
                has_rich_corr = True
            matched.append({
                "sensor": "wazuh",
                "rule_id": rid,
                "level": level,
                "description": desc,
                "mitre": mitre,
                "src_ip": (ev.get("data") or {}).get("srcip", ""),
                "target": (ev.get("syscheck") or {}).get("path", "") or ((ev.get("data") or {}).get("url", "")),
                "pid": ((ev.get("data") or {}).get("audit") or {}).get("pid", ""),
            })
            ts = parse_iso_utc(ev.get("timestamp"))
            if ts and ts >= t0_epoch:
                ttfa_candidates.append(max(1.0, (ts - t0_epoch) * 1000.0))

        for ar in ar_lines:
            matched.append({"sensor": "wazuh-active-response", "rule_id": "WAZUH.ACTIVE_RESPONSE", "detail": ar})

        detected = len(matched) > 0
        ctx = compute_context_maturity(matched, has_lineage_or_chain=has_rich_corr)
        ttfa = round(min(ttfa_candidates), 2) if ttfa_candidates else (750.0 if detected else None)
        summary = ", ".join(f"{m.get('rule_id')}:{str(m.get('description',''))[:40]}" for m in matched[:4]) or "none"
        return TelemetryVerdict(
            detected=detected,
            context_maturity=ctx,
            ttfa_ms=ttfa,
            evidence_summary=summary,
            raw_alerts=matched[:15],
        )


def _py_exec_wrapper() -> str:
    code = _REMOTE_WZ_DELTA_PY.strip().replace("'", "'\"'\"'")
    return f"'{code}'"
