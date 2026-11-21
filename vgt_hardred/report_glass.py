"""VGT Glass 2100 self-contained interactive HTML5 dashboard & Markdown final report generator."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from vgt_hardred.models import ContenderScorecard


def _esc(val: object) -> str:
    return html.escape(str(val), quote=True)


def generate_markdown_report(scorecards: list[ContenderScorecard], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ranked_sec = sorted(
        [s for s in scorecards if s.contender_id != "baseline"],
        key=lambda s: s.overall_score,
        reverse=True,
    )
    all_rows = ranked_sec + [s for s in scorecards if s.contender_id == "baseline"]
    winner = ranked_sec[0] if ranked_sec else (all_rows[0] if all_rows else None)

    lines: list[str] = [
        "# VGT HardRed Test — Gesamtbericht, Ranking & Gewinner",
        "",
        f"**Erstellt (UTC):** {datetime.now(timezone.utc).isoformat()}  ",
        "**Methodik:** VGT HardRed Test (4-Achsen-Modell: Efficacy 45% · FP-Resilienz 20% · TTFA/Schadensbegrenzung 20% · Overhead 15%; strikte Trennung Detection vs. Prevention TPR/FPR)  ",
        "",
    ]
    if winner:
        lines += [
            f"## Gesamtsieger: **{winner.contender_label}** ({winner.overall_score:.2f} / 100 · Gate `{winner.gate_status}`)",
            "",
        ]

    lines += [
        "## 1. Gesamt-Ranking & 4-Achsen-Matrix",
        "",
        "| Rang | Sicherheitssystem | Gesamt (0-100) | Achse 1: Effektivität | Achse 2: FP-Resilienz | Achse 3: Latenz & Eindämmung | Achse 4: System-Overhead | Gate |",
        "|---:|---|---:|---:|---:|---:|---:|---|",
    ]
    for idx, sc in enumerate(all_rows, start=1):
        rank_lbl = "Ref" if sc.contender_id == "baseline" else str(idx)
        lines.append(
            f"| {rank_lbl} | **{sc.contender_label}** (`{sc.snapshot}`) | **{sc.overall_score:.2f}** | "
            f"{sc.axis1_efficacy:.2f} | {sc.axis2_fp_resilience:.2f} | {sc.axis3_latency_containment:.2f} | "
            f"{sc.axis4_overhead:.2f} | `{sc.gate_status}` |"
        )

    lines += [
        "",
        "## 2. Domänen-Vergleich (Detection TPR vs. Prevention TPR · FPR · TTFA)",
        "",
        "| System | Domäne | Det TPR | Prev TPR | Det FPR | Prot FPR | Context (0-3) | Median TTFA (ms) | Damage Ratio | Score |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for sc in all_rows:
        for dom_name, ds in sc.domain_scores.items():
            ttfa_s = f"{ds.median_ttfa_ms:.1f}" if ds.median_ttfa_ms is not None else "—"
            dmg_s = f"{ds.avg_damage_ratio*100:.1f}%" if ds.avg_damage_ratio is not None else "—"
            lines.append(
                f"| {sc.contender_id} | `{dom_name}` | {ds.detection_tpr*100:.1f}% | {ds.prevention_tpr*100:.1f}% | "
                f"{ds.detection_fpr*100:.1f}% | {ds.protection_fpr*100:.1f}% | {ds.avg_context_maturity:.2f} | "
                f"{ttfa_s} | {dmg_s} | **{ds.domain_score:.1f}** |"
            )

    lines += [
        "",
        "## 3. System-Overhead, Durchsatz & Compliance-Posture",
        "",
        "| System | HTTP RPS | HTTP p50 (ms) | HTTP p95 (ms) | HTTP p99 (ms) | Sysbench EPS | FIO IOPS | Security RSS (MiB) | Security CPU (%) | Lynis Index | Aktive LSMs |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for sc in all_rows:
        p = sc.perf
        lines.append(
            f"| {sc.contender_id} | {p.http_rps:.1f} | {p.http_p50_ms:.2f} | {p.http_p95_ms:.2f} | {p.http_p99_ms:.2f} | "
            f"{p.sysbench_events_per_sec:.1f} | {p.fio_randwrite_iops:.1f} | {p.security_rss_mib:.1f} | {p.security_cpu_pct:.1f}% | "
            f"{sc.compliance_index} | {', '.join(p.lsm_active) or '—'} |"
        )

    lines += ["", "## 4. Gate-Bewertungen & Begründungen", ""]
    for sc in all_rows:
        lines.append(f"- **{sc.contender_label}** (`{sc.gate_status}`): {'; '.join(sc.gate_reasons)}")

    lines += [
        "",
        "## 5. Einzeltest-Matrix (Ground Truth vs. Ist-Ergebnis)",
        "",
        "| System | Case-ID | Domäne | Polarität | MITRE | Detected | Prevented | Context | TTFA (ms) | Damage | Evidenz |",
        "|---|---|---|---|---|---|---|---|---:|---|---|",
    ]
    for sc in all_rows:
        for cr in sc.case_results:
            ttfa = f"{cr.ttfa_ms:.1f}" if cr.ttfa_ms is not None else "—"
            dmg = f"{cr.pre_kill_damage}/{cr.pre_kill_total}" if cr.pre_kill_total else "—"
            ev = cr.evidence_summary.replace("|", "/")[:90]
            lines.append(
                f"| {sc.contender_id} | `{cr.case.case_id}` | `{cr.case.domain}` | {cr.case.polarity} | "
                f"`{cr.case.mitre_technique}` | {'YES' if cr.detected else 'NO'} | {'YES' if cr.prevented else 'NO'} | "
                f"{cr.context_maturity}/3 | {ttfa} | {dmg} | `{ev}` |"
            )

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def generate_glass_html_report(scorecards: list[ContenderScorecard], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ranked_sec = sorted(
        [s for s in scorecards if s.contender_id != "baseline"],
        key=lambda s: s.overall_score,
        reverse=True,
    )
    all_rows = ranked_sec + [s for s in scorecards if s.contender_id == "baseline"]
    winner = ranked_sec[0] if ranked_sec else (all_rows[0] if all_rows else None)

    case_rows_json = json.dumps(
        [
            {
                "contender": sc.contender_id,
                "case_id": cr.case.case_id,
                "domain": cr.case.domain,
                "category": cr.case.category,
                "title": cr.case.title,
                "polarity": cr.case.polarity,
                "mitre": cr.case.mitre_technique,
                "detected": cr.detected,
                "prevented": cr.prevented,
                "context": cr.context_maturity,
                "ttfa_ms": cr.ttfa_ms,
                "damage": f"{cr.pre_kill_damage}/{cr.pre_kill_total}" if cr.pre_kill_total else "-",
                "evidence": cr.evidence_summary,
            }
            for sc in all_rows
            for cr in sc.case_results
        ],
        ensure_ascii=False,
    )

    podium_html = ""
    for idx, sc in enumerate(all_rows, start=1):
        rank_txt = "Baseline Reference" if sc.contender_id == "baseline" else f"Rank #{idx}"
        badge_cls = "badge-pass" if sc.gate_status == "PASS" else ("badge-warn" if sc.gate_status == "CONDITIONAL" else "badge-fail")
        podium_html += f"""
        <article class="vgt-glass-surface card-podium">
          <div class="card-head">
            <span class="rank-pill">{_esc(rank_txt)}</span>
            <span class="gate-pill {badge_cls}">{_esc(sc.gate_status)}</span>
          </div>
          <h2>{_esc(sc.contender_label)}</h2>
          <p class="snap-meta">Snapshot: <code>{_esc(sc.snapshot)}</code></p>
          <div class="big-score">{sc.overall_score:.1f}<span>/100</span></div>
          <div class="axis-bars">
            <div class="axis-row"><span>Efficacy (45%)</span><div class="bar"><i style="width:{min(100, sc.axis1_efficacy):.1f}%"></i></div><b>{sc.axis1_efficacy:.1f}</b></div>
            <div class="axis-row"><span>FP Resilience (20%)</span><div class="bar"><i style="width:{min(100, sc.axis2_fp_resilience):.1f}%"></i></div><b>{sc.axis2_fp_resilience:.1f}</b></div>
            <div class="axis-row"><span>Speed & Containment (20%)</span><div class="bar"><i style="width:{min(100, sc.axis3_latency_containment):.1f}%"></i></div><b>{sc.axis3_latency_containment:.1f}</b></div>
            <div class="axis-row"><span>Low Overhead (15%)</span><div class="bar"><i style="width:{min(100, sc.axis4_overhead):.1f}%"></i></div><b>{sc.axis4_overhead:.1f}</b></div>
          </div>
        </article>"""

    domain_rows_html = ""
    for sc in all_rows:
        for dom_name, ds in sc.domain_scores.items():
            ttfa_s = f"{ds.median_ttfa_ms:.1f} ms" if ds.median_ttfa_ms is not None else "—"
            dmg_s = f"{ds.avg_damage_ratio*100:.1f}%" if ds.avg_damage_ratio is not None else "—"
            domain_rows_html += (
                f"<tr><td><strong>{_esc(sc.contender_id)}</strong></td><td><code>{_esc(dom_name)}</code></td>"
                f"<td>{ds.detection_tpr*100:.1f}%</td><td>{ds.prevention_tpr*100:.1f}%</td>"
                f"<td>{ds.detection_fpr*100:.1f}%</td><td>{ds.protection_fpr*100:.1f}%</td>"
                f"<td>{ds.avg_context_maturity:.2f}/3</td><td>{_esc(ttfa_s)}</td><td>{_esc(dmg_s)}</td>"
                f"<td><strong>{ds.domain_score:.1f}</strong></td></tr>\n"
            )

    perf_rows_html = ""
    for sc in all_rows:
        p = sc.perf
        perf_rows_html += (
            f"<tr><td><strong>{_esc(sc.contender_id)}</strong></td>"
            f"<td>{p.http_rps:.1f}</td><td>{p.http_p50_ms:.2f}</td><td>{p.http_p95_ms:.2f}</td><td>{p.http_p99_ms:.2f}</td>"
            f"<td>{p.sysbench_events_per_sec:.1f}</td><td>{p.fio_randwrite_iops:.1f}</td>"
            f"<td>{p.security_rss_mib:.1f} MiB</td><td>{p.security_cpu_pct:.1f}%</td>"
            f"<td><strong>{sc.compliance_index}</strong></td></tr>\n"
        )

    win_banner = (
        f"Overall Winner: {_esc(winner.contender_label)} — {winner.overall_score:.2f} / 100 (Gate: {_esc(winner.gate_status)})"
        if winner
        else "No contenders evaluated"
    )

    html_doc = f"""<!doctype html>
<html lang="de" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VGT HardRed Test · Live Benchmark Dashboard</title>
<style>
:root {{
  color-scheme: light;
  --vgt-bg-0: #eef2f0;
  --vgt-bg-1: #dce6e1;
  --vgt-text-primary: #15231f;
  --vgt-text-secondary: #485e57;
  --vgt-accent: #146c65;
  --vgt-accent-strong: #0d524c;
  --vgt-focus: #0b6dba;
  --vgt-pass: #146c43;
  --vgt-warn: #9a6700;
  --vgt-fail: #b42318;
  --vgt-glass-fill: rgb(255 255 255 / 76%);
  --vgt-glass-stroke: rgb(255 255 255 / 88%);
  --vgt-glass-shadow: 0 12px 32px rgb(19 36 31 / 9%);
  --vgt-fallback-surface: #f9fbfa;
  --vgt-radius: 18px;
  --vgt-blur: 11px;
  --vgt-font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --vgt-mono: ui-monospace, "Cascadia Mono", Consolas, monospace;
}}
[data-theme="dark"] {{
  color-scheme: dark;
  --vgt-bg-0: #0f1818;
  --vgt-bg-1: #1a2826;
  --vgt-text-primary: #f2f7f5;
  --vgt-text-secondary: #bfd0cb;
  --vgt-accent: #7bd6bb;
  --vgt-accent-strong: #a7edd8;
  --vgt-focus: #8cc8ff;
  --vgt-pass: #5dd89d;
  --vgt-warn: #f0b849;
  --vgt-fail: #f9857d;
  --vgt-glass-fill: rgb(28 44 41 / 86%);
  --vgt-glass-stroke: rgb(224 252 245 / 14%);
  --vgt-glass-shadow: 0 16px 40px rgb(0 0 0 / 28%);
  --vgt-fallback-surface: #1f302d;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  min-block-size: 100dvh;
  background: linear-gradient(145deg, var(--vgt-bg-0), var(--vgt-bg-1));
  color: var(--vgt-text-primary);
  font-family: var(--vgt-font);
  line-height: 1.5;
}}
.wrap {{ max-width: 1360px; margin: 0 auto; padding: 24px 20px 56px; }}
.vgt-glass-surface {{
  background: var(--vgt-fallback-surface);
  border: 1px solid var(--vgt-glass-stroke);
  border-radius: var(--vgt-radius);
  box-shadow: var(--vgt-glass-shadow);
}}
@supports ((-webkit-backdrop-filter: blur(1px)) or (backdrop-filter: blur(1px))) {{
  .vgt-glass-surface {{
    background: var(--vgt-glass-fill);
    -webkit-backdrop-filter: blur(var(--vgt-blur)) saturate(1.06);
    backdrop-filter: blur(var(--vgt-blur)) saturate(1.06);
  }}
}}
@media (prefers-reduced-transparency: reduce) {{
  .vgt-glass-surface {{ background: var(--vgt-fallback-surface); -webkit-backdrop-filter: none; backdrop-filter: none; }}
}}
header.topbar {{
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 16px; padding: 20px 24px; margin-bottom: 20px;
}}
header.topbar h1 {{ margin: 0; font-size: clamp(1.3rem, 2.5vw, 1.85rem); letter-spacing: -0.02em; }}
.subtitle {{ margin: 4px 0 0; color: var(--vgt-text-secondary); font-size: 0.94rem; }}
.btn-theme {{
  border: 1px solid var(--vgt-glass-stroke); background: var(--vgt-accent); color: #fff;
  padding: 10px 16px; border-radius: 11px; font-weight: 600; cursor: pointer;
}}
[data-theme="dark"] .btn-theme {{ color: #0f1818; }}
.winner-strip {{
  padding: 16px 22px; margin-bottom: 22px; font-weight: 700; font-size: 1.05rem;
  border-inline-start: 5px solid var(--vgt-accent);
}}
.podium-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 18px; margin-bottom: 24px;
}}
.card-podium {{ padding: 20px; }}
.card-podium h2 {{ margin: 10px 0 4px; font-size: 1.12rem; }}
.snap-meta {{ margin: 0 0 12px; color: var(--vgt-text-secondary); font-size: 0.85rem; }}
.card-head {{ display: flex; justify-content: space-between; align-items: center; }}
.rank-pill {{ font-size: 0.8rem; font-weight: 700; color: var(--vgt-accent); text-transform: uppercase; letter-spacing: 0.04em; }}
.gate-pill {{ font-size: 0.78rem; font-weight: 700; padding: 3px 10px; border-radius: 999px; border: 1px solid currentColor; }}
.badge-pass {{ color: var(--vgt-pass); }}
.badge-warn {{ color: var(--vgt-warn); }}
.badge-fail {{ color: var(--vgt-fail); }}
.big-score {{ font-size: 2.25rem; font-weight: 800; letter-spacing: -0.03em; margin-bottom: 14px; }}
.big-score span {{ font-size: 1rem; font-weight: 500; color: var(--vgt-text-secondary); }}
.axis-bars {{ display: grid; gap: 8px; }}
.axis-row {{ display: grid; grid-template-columns: 150px 1fr 44px; align-items: center; gap: 8px; font-size: 0.84rem; }}
.bar {{ height: 8px; border-radius: 99px; background: rgb(128 150 144 / 20%); overflow: hidden; }}
.bar i {{ display: block; height: 100%; background: var(--vgt-accent); border-radius: 99px; }}
section.panel {{ padding: 20px 22px; margin-bottom: 22px; overflow-x: auto; }}
section.panel h3 {{ margin: 0 0 14px; font-size: 1.08rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid rgb(120 140 135 / 18%); vertical-align: top; }}
th {{ color: var(--vgt-text-secondary); font-weight: 600; white-space: nowrap; }}
code {{ font-family: var(--vgt-mono); font-size: 0.83em; }}
.filters {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }}
.filters select, .filters input {{
  padding: 8px 12px; border-radius: 10px; border: 1px solid rgb(120 140 135 / 35%);
  background: transparent; color: inherit; font-family: inherit;
}}
:where(button, select, input):focus-visible {{ outline: 3px solid var(--vgt-focus); outline-offset: 2px; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="vgt-glass-surface topbar">
    <div>
      <h1>VGT HardRed Test · Security Benchmark Matrix</h1>
      <p class="subtitle">Reproduzierbarer Live-Vergleich auf KVM/VirtualBox HWE 7.0 (`192.168.56.50`) · OSI-Open-Source-Suites</p>
    </div>
    <button type="button" class="btn-theme" id="themeBtn">Toggle Dark/Light Glass</button>
  </header>

  <div class="vgt-glass-surface winner-strip">{win_banner}</div>

  <div class="podium-grid">{podium_html}</div>

  <section class="vgt-glass-surface panel">
    <h3>Domänen-Ergebnisse: Detection TPR vs. Prevention TPR &amp; False-Positive-Rate</h3>
    <table>
      <thead><tr><th>System</th><th>Domäne</th><th>Det TPR</th><th>Prev TPR</th><th>Det FPR</th><th>Prot FPR</th><th>Context</th><th>Median TTFA</th><th>Damage</th><th>Score</th></tr></thead>
      <tbody>{domain_rows_html}</tbody>
    </table>
  </section>

  <section class="vgt-glass-surface panel">
    <h3>System-Overhead, HTTP-Latenz &amp; Compliance</h3>
    <table>
      <thead><tr><th>System</th><th>HTTP RPS</th><th>p50 (ms)</th><th>p95 (ms)</th><th>p99 (ms)</th><th>Sysbench EPS</th><th>FIO IOPS</th><th>Security RSS</th><th>CPU</th><th>Lynis Index</th></tr></thead>
      <tbody>{perf_rows_html}</tbody>
    </table>
  </section>

  <section class="vgt-glass-surface panel">
    <h3>Einzeltest-Inspektor ({sum(len(s.case_results) for s in all_rows)} Testläufe)</h3>
    <div class="filters">
      <select id="fContender"><option value="">Alle Systeme</option></select>
      <select id="fDomain"><option value="">Alle Domänen</option></select>
      <select id="fPolarity"><option value="">Attack + Benign</option><option value="attack">Attack</option><option value="benign">Benign</option></select>
      <input id="fSearch" type="search" placeholder="Suche Case-ID / MITRE / Evidenz...">
    </div>
    <table>
      <thead><tr><th>System</th><th>Case-ID</th><th>Domäne</th><th>Polarität</th><th>MITRE</th><th>Det</th><th>Prev</th><th>Ctx</th><th>TTFA</th><th>Dmg</th><th>Evidenz</th></tr></thead>
      <tbody id="caseBody"></tbody>
    </table>
  </section>
</div>
<script>
const DATA = {case_rows_json};
const btn = document.getElementById('themeBtn');
btn.addEventListener('click', () => {{
  const root = document.documentElement;
  root.setAttribute('data-theme', root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}});
const fC = document.getElementById('fContender');
const fD = document.getElementById('fDomain');
const fP = document.getElementById('fPolarity');
const fS = document.getElementById('fSearch');
[...new Set(DATA.map(d => d.contender))].forEach(c => fC.add(new Option(c, c)));
[...new Set(DATA.map(d => d.domain))].forEach(d => fD.add(new Option(d, d)));

function renderCases() {{
  const cv = fC.value, dv = fD.value, pv = fP.value, sv = fS.value.trim().toLowerCase();
  const tbody = document.getElementById('caseBody');
  const rows = DATA.filter(r =>
    (!cv || r.contender === cv) &&
    (!dv || r.domain === dv) &&
    (!pv || r.polarity === pv) &&
    (!sv || (r.case_id + ' ' + r.title + ' ' + r.mitre + ' ' + r.evidence).toLowerCase().includes(sv))
  );
  tbody.innerHTML = rows.map(r => {{
    const esc = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
    return `<tr><td><strong>${{esc(r.contender)}}</strong></td><td><code>${{esc(r.case_id)}}</code></td><td><code>${{esc(r.domain)}}</code></td>` +
      `<td>${{esc(r.polarity)}}</td><td><code>${{esc(r.mitre)}}</code></td>` +
      `<td>${{r.detected ? 'YES' : 'no'}}</td><td>${{r.prevented ? 'YES' : 'no'}}</td>` +
      `<td>${{r.context}}/3</td><td>${{r.ttfa_ms !== null ? r.ttfa_ms + ' ms' : '—'}}</td>` +
      `<td>${{esc(r.damage)}}</td><td><code>${{esc(r.evidence.slice(0, 110))}}</code></td></tr>`;
  }}).join('');
}}
[fC, fD, fP, fS].forEach(el => el.addEventListener('input', renderCases));
renderCases();
</script>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path
