"""GeDefense Linux 6.1.2 REST API & evidence telemetry adapter."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from vgt_hardred.adapters.base import AdapterCursor, TelemetryVerdict, compute_context_maturity, parse_iso_utc
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController

_REMOTE_SNAPSHOT_PY = r'''
import json, subprocess, urllib.request

token = subprocess.check_output(
    ["sudo", "cat", "/var/lib/vgt/gedefense-access/dashboard.token"], text=True
).strip()

def get_json(path):
    req = urllib.request.Request(
        f"http://127.0.0.1:9844{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"_error": str(exc)}

out = {
    "status": get_json("/api/v1/status"),
    "l7": get_json("/api/v1/l7/findings"),
    "kinetic_live": get_json("/api/v1/kinetic/live"),
    "kinetic_events": get_json("/api/v1/kinetic/events"),
    "titan_events": get_json("/api/v1/titan/events"),
    "titan_exec_events": get_json("/api/v1/titan/exec/events"),
    "worker_guard": get_json("/api/v1/worker-guard/status"),
    "worker_guard_events": get_json("/api/v1/worker-guard/events"),
    "styx": get_json("/api/v1/styx/status"),
    "tls_sensor": get_json("/api/v1/tls-sensor/status"),
    "responses": get_json("/api/v1/responses"),
    "attack_stories": get_json("/api/v1/xdr/attack-stories"),
    "forensics": get_json("/api/v1/forensics/export?format=json"),
}
print(json.dumps(out))
'''


class GeDefenseAdapter:
    contender_id = "gedefense"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["gedefense-control", "gedefense-core", "gedefense-access"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            snap = self._fetch_snapshot()
            st = snap.get("status")
            if isinstance(st, dict) and st.get("core_connected") is True:
                return
            time.sleep(2.0)

    def clear_attacker_blocks(self) -> None:
        unban_py = r'''
import json, subprocess, uuid, urllib.request
token = subprocess.check_output(["sudo", "cat", "/var/lib/vgt/gedefense-access/dashboard.token"], text=True).strip()
def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    hdr = {"Authorization": f"Bearer {token}", "X-VGT-Request-ID": str(uuid.uuid4())}
    if data: hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:9844{path}", data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r: return json.loads(r.read().decode())
    except Exception: return {}
st = api("GET", "/api/v1/status")
for b in (st.get("blocks") or []):
    bid, tgt = b.get("id"), b.get("target")
    if bid and tgt:
        api("DELETE", f"/api/v1/blocks/{bid}", {"confirmation": f"REMOVE BLOCK {tgt}", "reason": "Benchmark between-case IP unban"})
'''
        self.vm.ssh("python3 -", timeout_sec=15, stdin_text=unban_py)

    def _fetch_snapshot(self) -> dict[str, Any]:
        rc, out, err = self.vm.ssh("python3 -", timeout_sec=20, stdin_text=_REMOTE_SNAPSHOT_PY)
        if rc != 0:
            return {"_ssh_error": err.strip() or f"rc={rc}"}
        try:
            return json.loads(out.strip().splitlines()[-1])
        except Exception as exc:
            return {"_parse_error": str(exc)}

    def capture_cursor(self) -> AdapterCursor:
        snap = self._fetch_snapshot()
        return AdapterCursor(captured_utc=datetime.now(timezone.utc).isoformat(), state=snap)

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 1.5,
    ) -> TelemetryVerdict:
        if settle_sec > 0:
            time.sleep(settle_sec)
        before = cursor.state
        after = self._fetch_snapshot()
        t0_epoch = parse_iso_utc(started_utc) or 0.0

        alerts: list[dict[str, Any]] = []
        ttfa_candidates: list[float] = []
        has_story_or_lineage = False

        # 1. Status events
        b_ev_ids = {e.get("id") for e in (before.get("status", {}).get("events") or []) if isinstance(e, dict)}
        for ev in (after.get("status", {}).get("events") or []):
            if not isinstance(ev, dict):
                continue
            eid = ev.get("id")
            ev_ts = parse_iso_utc(ev.get("time"))
            if (eid and eid not in b_ev_ids) or (ev_ts and ev_ts >= t0_epoch - 0.5):
                sev = str(ev.get("severity", "")).lower()
                kind = str(ev.get("kind", ""))
                # Exclude pure background housekeeping / lifecycle info events
                if kind in {
                    "chronos.merkle_verified",
                    "web_exposure.posture",
                    "feeds.auto_synced",
                    "feeds.kernel_reapplied",
                    "transaction.runtime_drift",
                    "kernel.mitigation_auxiliary_applied",
                    "xdr.styx_flow_sensor_recovered",
                    "xdr.styx_flow_sensor_degraded",
                    "xdr.incident_log_rotated",
                    "release.recovery",
                    "release.qualified",
                    "release.phase_changed",
                    "fim.baseline_created",
                    "deception.honeypot_armed",
                } or kind.startswith(("feeds.", "chronos.", "release.", "web_exposure.", "kernel.mitigation_", "transaction.", "xdr.styx_flow_sensor_", "xdr.incident_log_")) or (sev == "info" and "audit" in kind):
                    continue
                alerts.append({"sensor": ev.get("source", "status"), "kind": kind, "message": ev.get("message", ""), "target": ev.get("target", ""), "severity": sev})
                if ev_ts and ev_ts >= t0_epoch:
                    ttfa_candidates.append(max(1.0, (ev_ts - t0_epoch) * 1000.0))

        # 2. L7 WAF findings & counters
        b_l7 = before.get("l7", {}) if isinstance(before.get("l7"), dict) else {}
        a_l7 = after.get("l7", {}) if isinstance(after.get("l7"), dict) else {}
        b_l7_st = b_l7.get("status") or {}
        a_l7_st = a_l7.get("status") or {}
        b_l7_findings = {f.get("id") or json.dumps(f, sort_keys=True) for f in (b_l7.get("findings") or [])}
        for f in (a_l7.get("findings") or []):
            fk = f.get("id") or json.dumps(f, sort_keys=True)
            if fk not in b_l7_findings:
                alerts.append({"sensor": "l7-waf", "uri": f.get("uri", f.get("path", "")), "rule_id": f.get("rule_id", f.get("rule", "L7")), "src_ip": f.get("remote_addr", ""), **f})
                ts = parse_iso_utc(f.get("time") or f.get("observed_utc"))
                if ts and ts >= t0_epoch:
                    ttfa_candidates.append(max(1.0, (ts - t0_epoch) * 1000.0))

        l7_delta = (
            int(a_l7_st.get("findings_total", 0)) - int(b_l7_st.get("findings_total", 0))
            + int(a_l7_st.get("blocked_total", 0)) - int(b_l7_st.get("blocked_total", 0))
            + int(a_l7_st.get("inline_blocked_total", 0)) - int(b_l7_st.get("inline_blocked_total", 0))
            + int(a_l7_st.get("rate_limited_total", 0)) - int(b_l7_st.get("rate_limited_total", 0))
        )
        if l7_delta > 0 and not any(a.get("sensor") == "l7-waf" for a in alerts):
            alerts.append({"sensor": "l7-waf", "rule_id": "L7.INLINE", "delta": l7_delta})

        # 3. Kinetic / XDP drops & bans
        b_k_st = (before.get("kinetic_live") or {}).get("status") or {}
        a_k_st = (after.get("kinetic_live") or {}).get("status") or {}
        for key in ("bans_enforced_total", "portscans_total", "velocity_bursts_total", "l7_strikes_total"):
            d = int(a_k_st.get(key, 0)) - int(b_k_st.get(key, 0))
            if d > 0:
                alerts.append({"sensor": "kinetic-xdp", "rule_id": f"KINETIC.{key}", "delta": d})
        k_drops_delta = int((after.get("kinetic_events") or {}).get("drops", 0)) - int((before.get("kinetic_events") or {}).get("drops", 0))
        if k_drops_delta > 0:
            alerts.append({"sensor": "kinetic-xdp", "rule_id": "KINETIC.XDP_DROP", "delta": k_drops_delta})

        # 4. TITAN-Exec denied/blocked exec events (action != 1 or rule_id != TITAN.EXEC_AUDIT or sandbox match)
        b_te = before.get("titan_exec_events", {}).get("events") or []
        a_te = after.get("titan_exec_events", {}).get("events") or []
        b_te_sigs = {(e.get("ts_ns"), e.get("pid"), e.get("comm")) for e in b_te if isinstance(e, dict)}
        for ev in a_te:
            if not isinstance(ev, dict):
                continue
            sig = (ev.get("ts_ns"), ev.get("pid"), ev.get("comm"))
            if sig in b_te_sigs:
                continue
            rule_id = str(ev.get("rule_id", ""))
            action = int(ev.get("action", 1))
            if action != 1 or ("DENY" in rule_id or "BLOCK" in rule_id or "UNTRUSTED" in rule_id or "CONTAIN" in rule_id):
                alerts.append({"sensor": "titan-exec", "pid": ev.get("pid"), "process": ev.get("comm"), "rule_id": rule_id, "action": action, "lineage": True})
                has_story_or_lineage = True

        # 5. Worker Guard denials
        b_wg = (before.get("worker_guard") or {}).get("counters") or {}
        a_wg = (after.get("worker_guard") or {}).get("counters") or {}
        wg_delta = (
            (int(a_wg.get("denied_exec", 0)) - int(b_wg.get("denied_exec", 0)))
            + (int(a_wg.get("denied_mmap", 0)) - int(b_wg.get("denied_mmap", 0)))
            + (int(a_wg.get("events", 0)) - int(b_wg.get("events", 0)))
        )
        if wg_delta > 0:
            alerts.append({"sensor": "worker-guard", "rule_id": "WORKER_GUARD", "delta": wg_delta, "lineage": True})
            has_story_or_lineage = True

        # 6. StyX policy drops
        b_styx = (before.get("styx") or {}).get("kernel_health") or {}
        a_styx = (after.get("styx") or {}).get("kernel_health") or {}
        styx_drops = int(a_styx.get("PolicyDrops", 0)) - int(b_styx.get("PolicyDrops", 0))
        if styx_drops > 0:
            alerts.append({"sensor": "styx-egress", "rule_id": "STYX.POLICY_DROP", "delta": styx_drops, "lineage": True})
            has_story_or_lineage = True

        # 7. XDR attack stories / incidents / responses delta
        b_stories = before.get("attack_stories") if isinstance(before.get("attack_stories"), list) else []
        a_stories = after.get("attack_stories") if isinstance(after.get("attack_stories"), list) else []
        if len(a_stories) > len(b_stories):
            for st in a_stories[len(b_stories):]:
                alerts.append({"sensor": "xdr-dag", "chain_id": st.get("chain_id"), "attack_story": True, "nodes": len(st.get("nodes", []))})
            has_story_or_lineage = True

        b_xdr = (before.get("forensics") or {}).get("xdr") or {}
        a_xdr = (after.get("forensics") or {}).get("xdr") or {}
        inc_delta = int(a_xdr.get("incidents_total", 0)) - int(b_xdr.get("incidents_total", 0))
        act_delta = int(a_xdr.get("actions_total", 0)) - int(b_xdr.get("actions_total", 0))
        if inc_delta > 0 or act_delta > 0:
            alerts.append({"sensor": "xdr", "rule_id": "XDR.INCIDENT", "incidents_delta": inc_delta, "actions_delta": act_delta, "lineage": True})
            has_story_or_lineage = True

        b_resp = before.get("responses") if isinstance(before.get("responses"), list) else []
        a_resp = after.get("responses") if isinstance(after.get("responses"), list) else []
        if len(a_resp) > len(b_resp):
            alerts.append({"sensor": "response-broker", "rule_id": "ACTIVE_RESPONSE", "delta": len(a_resp) - len(b_resp)})

        # 8. TLS sensor storm / findings
        b_tls = (before.get("tls_sensor") or {}).get("tls_engine") or {}
        a_tls = (after.get("tls_sensor") or {}).get("tls_engine") or {}
        if int(a_tls.get("findings", 0)) > int(b_tls.get("findings", 0)):
            alerts.append({"sensor": "tls-sensor", "rule_id": "TLS.ENGINE", "delta": int(a_tls.get("findings", 0)) - int(b_tls.get("findings", 0))})

        detected = len(alerts) > 0
        ctx = compute_context_maturity(alerts, has_lineage_or_chain=has_story_or_lineage)
        ttfa = round(min(ttfa_candidates), 2) if ttfa_candidates else (250.0 if detected else None)
        summary = ", ".join(str(a.get("rule_id") or a.get("kind") or a.get("sensor")) for a in alerts[:5]) or "none"
        return TelemetryVerdict(
            detected=detected,
            context_maturity=ctx,
            ttfa_ms=ttfa,
            evidence_summary=summary,
            raw_alerts=alerts[:15],
        )
