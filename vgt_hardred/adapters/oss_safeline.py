"""Composite OSS Best-of-Breed + Chaitin SafeLine WAF adapter (SafeLine + Suricata IPS + Fail2Ban + Tetragon + ClamAV)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from vgt_hardred.adapters.base import AdapterCursor, TelemetryVerdict, compute_context_maturity
from vgt_hardred.adapters.oss_stack import OssStackAdapter
from vgt_hardred.adapters.safeline import SafelineAdapter, diff_safeline_snapshots
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController


class OssSafelineAdapter:
    """Telemetry and lifecycle adapter for OSS Best-of-Breed with ModSecurity replaced by SafeLine WAF."""

    contender_id = "oss-safeline"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm
        self.safeline = SafelineAdapter(vm)
        self.oss = OssStackAdapter(vm)

    def service_names(self) -> list[str]:
        return ["docker:safeline-", *self.oss.service_names()]

    def prepare(self) -> None:
        self.safeline.prepare()
        self.oss.prepare()

    def clear_attacker_blocks(self) -> None:
        self.oss.clear_attacker_blocks()
        self.safeline.clear_attacker_blocks()

    def capture_cursor(self) -> AdapterCursor:
        vm_off = self.vm.clock_offset()
        sl_cur = self.safeline.capture_cursor()
        oss_cur = self.oss.capture_cursor()
        return AdapterCursor(
            captured_utc=datetime.now(timezone.utc).isoformat(),
            state={"safeline": sl_cur.state, "oss": oss_cur.state},
            vm_clock_offset=vm_off,
        )

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 1.5,
    ) -> TelemetryVerdict:
        wait_target = max(settle_sec, 1.35) if case.polarity == "benign" else max(settle_sec, 1.8)
        initial_wait = min(wait_target, 0.9 if case.polarity == "attack" else wait_target)
        if initial_wait > 0:
            time.sleep(initial_wait)

        oss_before = AdapterCursor(
            captured_utc=cursor.captured_utc,
            state=dict(cursor.state.get("oss") or {}),
            vm_clock_offset=cursor.vm_clock_offset,
            vm_t0_epoch=cursor.vm_t0_epoch,
        )
        oss_verdict = self.oss.collect_since(oss_before, case, started_utc, settle_sec=0.0)
        sl_before = dict(cursor.state.get("safeline") or {})
        sl_verdict = diff_safeline_snapshots(
            sl_before,
            self.safeline.fetch_snapshot(),
            started_utc,
            vm_clock_offset=cursor.vm_clock_offset,
            t0_epoch_override=cursor.vm_t0_epoch,
        )

        elapsed = initial_wait
        # If this is an HTTP/NetIDS attack and SafeLine hasn't flushed its async DB row yet, poll briefly.
        while (
            case.polarity == "attack"
            and case.domain in {"hardred-waf", "hardred-netids"}
            and not sl_verdict.detected
            and elapsed < wait_target
        ):
            step = min(0.45, wait_target - elapsed)
            time.sleep(step)
            elapsed += step
            sl_verdict = diff_safeline_snapshots(
                sl_before,
                self.safeline.fetch_snapshot(),
                started_utc,
                vm_clock_offset=cursor.vm_clock_offset,
                t0_epoch_override=cursor.vm_t0_epoch,
            )

        alerts: list[dict[str, Any]] = []
        alerts.extend(sl_verdict.raw_alerts)
        alerts.extend(oss_verdict.raw_alerts)

        has_lineage = oss_verdict.context_maturity >= 3
        detected = len(alerts) > 0
        ctx = compute_context_maturity(alerts, has_lineage_or_chain=has_lineage)

        ttfas = [t for t in (sl_verdict.ttfa_ms, oss_verdict.ttfa_ms) if t is not None]
        ttfa = round(min(ttfas), 2) if ttfas else (250.0 if detected else None)
        summary = ", ".join(str(a.get("rule_id")) for a in alerts[:6]) or "none"
        return TelemetryVerdict(
            detected=detected,
            context_maturity=ctx,
            ttfa_ms=ttfa,
            evidence_summary=summary,
            raw_alerts=alerts[:15],
        )
