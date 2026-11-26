"""Open-Source Best-of-Breed stack adapter (ModSecurity/OWASP CRS + Suricata IPS + Fail2Ban + Cilium Tetragon + ClamAV)."""

from __future__ import annotations

import json
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
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController

_REMOTE_OSS_OFFSET_PY = r'''
import json, os

FILES = {
    "modsec": "/var/log/nginx/modsec_audit.log",
    "suricata_eve": "/var/log/suricata/eve.json",
    "fail2ban": "/var/log/fail2ban.log",
    "tetragon": "/var/log/tetragon/tetragon.log",
    "clamonacc": "/var/log/clamav/clamonacc.log",
    "clamd": "/var/log/clamav/clamav.log",
}
out = {}
for k, p in FILES.items():
    try:
        out[k] = os.stat(p).st_size
    except FileNotFoundError:
        out[k] = 0
print(json.dumps(out))
'''

_REMOTE_OSS_DELTA_PY = r'''
import json, sys

offs = json.loads(sys.stdin.read())
FILES = {
    "modsec": "/var/log/nginx/modsec_audit.log",
    "suricata_eve": "/var/log/suricata/eve.json",
    "fail2ban": "/var/log/fail2ban.log",
    "tetragon": "/var/log/tetragon/tetragon.log",
    "clamonacc": "/var/log/clamav/clamonacc.log",
    "clamd": "/var/log/clamav/clamav.log",
}

def read_tail(path, off, limit=300):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            start = off if end >= off else 0
            f.seek(start)
            data = f.read(4 * 1024 * 1024).decode("utf-8", errors="replace").splitlines()
            return [ln.strip() for ln in data if ln.strip()][-limit:]
    except FileNotFoundError:
        return []

out = {}
for k, p in FILES.items():
    out[k] = read_tail(p, int(offs.get(k, 0)))
print(json.dumps(out))
'''


def _py_exec_wrapper() -> str:
    code = _REMOTE_OSS_DELTA_PY.strip().replace("'", "'\"'\"'")
    return f"'{code}'"


class OssStackAdapter:
    contender_id = "oss-stack"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["tetragon", "suricata", "fail2ban-server", "clamd", "clamonacc"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()
        self.vm.ssh(
            "sudo systemctl is-active tetragon suricata fail2ban clamav-daemon clamav-clamonacc >/dev/null 2>&1 || true",
            timeout_sec=15,
        )
        self.vm.measure_clock_offset(force_refresh=True)

    def clear_attacker_blocks(self) -> None:
        self.vm.ssh(
            "sudo fail2ban-client unban --all 2>/dev/null || true; "
            "sudo nft flush set inet hardred_ips blocklist_v4 2>/dev/null || true",
            timeout_sec=15,
        )

    def capture_cursor(self) -> AdapterCursor:
        vm_off = self.vm.clock_offset()
        rc, out, _ = self.vm.ssh("sudo python3 -", timeout_sec=15, stdin_text=_REMOTE_OSS_OFFSET_PY)
        state = {"modsec": 0, "suricata_eve": 0, "fail2ban": 0, "tetragon": 0, "clamonacc": 0, "clamd": 0}
        if rc == 0 and out.strip():
            try:
                state = json.loads(out.strip().splitlines()[-1])
            except Exception:
                pass
        return AdapterCursor(
            captured_utc=datetime.now(timezone.utc).isoformat(),
            state=state,
            vm_clock_offset=vm_off,
        )

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 1.5,
    ) -> TelemetryVerdict:
        if settle_sec > 0:
            time.sleep(settle_sec)
        payload = json.dumps(cursor.state)
        rc, out, _ = self.vm.ssh(
            f"sudo python3 -c {_py_exec_wrapper()} ",
            timeout_sec=25,
            stdin_text=payload,
        )
        deltas: dict[str, list[str]] = {}
        if rc == 0 and out.strip():
            try:
                deltas = json.loads(out.strip().splitlines()[-1])
            except Exception:
                deltas = {}

        t0_epoch = effective_t0_epoch(started_utc, cursor)
        alerts: list[dict[str, Any]] = []
        ttfa_candidates: list[float] = []
        has_lineage = False

        # 1. ModSecurity / OWASP CRS audit lines
        for line in deltas.get("modsec", []):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            tx = obj.get("transaction") if isinstance(obj, dict) else None
            if not isinstance(tx, dict):
                continue
            src_ip = str(tx.get("client_ip", ""))
            uri = str((tx.get("request") or {}).get("uri", ""))
            http_code = int((tx.get("response") or {}).get("http_code") or 200)
            msgs = [m for m in (tx.get("messages") or []) if isinstance(m, dict)]
            if not msgs:
                continue
            # CRS 920350 ("Host header is a numeric IP address", score +3 < 5)
            # logs to modsec_audit.log even on 200 OK; ignore non-blocking 920350-only noise.
            non_ip_notice = [
                m for m in msgs
                if str(((m.get("details") or {}).get("ruleId")) or "") != "920350"
            ]
            if not non_ip_notice and http_code < 400:
                continue
            # Prefer a specific attack/CRS rule over generic anomaly-threshold evaluation rules (949110/980130).
            specific = [
                m for m in non_ip_notice
                if str(((m.get("details") or {}).get("ruleId")) or "") not in {"949110", "980130"}
            ]
            chosen = (specific or non_ip_notice or msgs)[0]
            details = chosen.get("details") if isinstance(chosen.get("details"), dict) else {}
            rid = str(details.get("ruleId") or "modsec-crs")
            alerts.append({
                "sensor": "modsecurity-crs",
                "rule_id": rid,
                "src_ip": src_ip,
                "uri": uri,
                "http_code": http_code,
                "msg": str(chosen.get("message", ""))[:120],
            })

        # 2. Suricata Inline IPS alerts (eve.json)
        for line in deltas.get("suricata_eve", []):
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue
            etype = ev.get("event_type")
            if etype not in {"alert", "drop"}:
                continue
            src_ip = str(ev.get("src_ip", ""))
            if src_ip == "10.0.2.2":
                continue
            al = ev.get("alert") or {}
            sig = str(al.get("signature") or etype)
            sid = str(al.get("signature_id") or "")
            alerts.append({
                "sensor": "suricata-ips",
                "rule_id": f"suricata:{sid}" if sid else "suricata",
                "signature": sig,
                "src_ip": src_ip,
                "dest_port": ev.get("dest_port"),
                "action": str(al.get("action", "allowed")),
            })
            ts = parse_iso_utc(ev.get("timestamp"))
            ttfa_val = compute_event_ttfa_ms(ts, t0_epoch, jitter_grace_sec=0.020)
            if ttfa_val is not None:
                ttfa_candidates.append(ttfa_val)

        # 3. Fail2Ban bans
        for line in deltas.get("fail2ban", []):
            if " Ban " in line and "10.0.2.2" not in line:
                alerts.append({
                    "sensor": "fail2ban",
                    "rule_id": "fail2ban.ban",
                    "detail": line[-140:],
                })

        # 4. Cilium Tetragon kprobe/tracepoint/lsm enforcement & behavioral alerts
        for line in deltas.get("tetragon", []):
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue
            kp = None
            for ev_key in ("process_kprobe", "process_tracepoint", "process_lsm"):
                cand = ev.get(ev_key)
                if isinstance(cand, dict):
                    kp = cand
                    break
            if kp is None:
                continue
            proc = kp.get("process") or {}
            parent = kp.get("parent") or {}
            binary = str(proc.get("binary", ""))
            fn = str(kp.get("function_name") or kp.get("subsys") or "")
            policy = str(kp.get("policy_name", ""))
            action = str(kp.get("action", ""))
            # Ignore benign system housekeeping unless explicit policy hit
            if not policy:
                continue
            if parent:
                has_lineage = True
            alerts.append({
                "sensor": "cilium-tetragon",
                "rule_id": f"{policy}/{fn}",
                "action": action,
                "pid": proc.get("pid"),
                "ppid": parent.get("pid"),
                "exe": binary,
                "parent": parent.get("binary", ""),
            })
            ts = parse_iso_utc(ev.get("time"))
            ttfa_val = compute_event_ttfa_ms(ts, t0_epoch, jitter_grace_sec=0.020)
            if ttfa_val is not None:
                ttfa_candidates.append(ttfa_val)

        # 5. ClamAV On-Access malware alerts
        for line in deltas.get("clamonacc", []) + deltas.get("clamd", []):
            if "FOUND" in line or "moved to" in line:
                alerts.append({
                    "sensor": "clamav-onaccess",
                    "rule_id": "clamav.onaccess.malware",
                    "target": line[-140:],
                })

        detected = len(alerts) > 0
        ctx = compute_context_maturity(alerts, has_lineage_or_chain=has_lineage)
        ttfa = round(min(ttfa_candidates), 2) if ttfa_candidates else (250.0 if detected else None)
        summary = ", ".join(str(a.get("rule_id")) for a in alerts[:5]) or "none"
        return TelemetryVerdict(
            detected=detected,
            context_maturity=ctx,
            ttfa_ms=ttfa,
            evidence_summary=summary,
            raw_alerts=alerts[:15],
        )
