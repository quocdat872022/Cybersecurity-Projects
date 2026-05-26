"""
©AngelaMos | 2026
html_report.py

Standalone HTML reporter for DLP scan results.

Produces a single self-contained .html file (no external dependencies) with:
  • A top summary bar: counts by severity + framework breakdown
  • A donut chart rendered in pure SVG (no canvas/Chart.js needed)
  • A sortable findings table (click any column header to sort)
  • Severity colour coding matching the console reporter
    critical → #c0392b (bold red)
    high     → #e74c3c (red)
    medium   → #f39c12 (yellow/amber)
    low      → #27ae60 (green)

Usage (wire into engine.py and commands/scan.py – see patches below):
    reporter = HtmlReporter()
    html_string = reporter.generate(result)
"""

from __future__ import annotations

import html
from datetime import datetime, UTC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dlp_scanner.models import ScanResult, Finding
    

# ── Severity palette (mirrors SEVERITY_COLORS in constants.py) ──────────────
_SEV_HEX: dict[str, str] = {
    "critical": "#c0392b",
    "high":     "#e74c3c",
    "medium":   "#f39c12",
    "low":      "#27ae60",
}

_SEV_BG: dict[str, str] = {
    "critical": "#fdecea",
    "high":     "#fef0ef",
    "medium":   "#fef9ec",
    "low":      "#eafaf1",
}

_SEV_ORDER = ("critical", "high", "medium", "low")

# Truncate snippets at 80 chars for HTML table readability
_SNIPPET_MAX = 80


# ── Public class ─────────────────────────────────────────────────────────────

class HtmlReporter:
    """
    Generates a standalone HTML report from a ScanResult.

    Implements the Reporter protocol: ``generate(result) -> str``.
    The returned string is a complete, self-contained HTML document.
    """

    def generate(self, result: "ScanResult") -> str:
        """Return a complete HTML document as a string."""
        generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        by_sev   = result.findings_by_severity
        by_fw    = result.findings_by_framework
        total    = len(result.findings)

        summary_cards_html  = _build_summary_cards(total, by_sev, result)
        chart_html          = _build_donut_chart(by_sev)
        framework_html      = _build_framework_table(by_fw)
        findings_table_html = _build_findings_table(result.findings)

        duration = ""
        if result.scan_completed_at:
            delta = result.scan_completed_at - result.scan_started_at
            duration = f" &nbsp;·&nbsp; Duration: {delta.total_seconds():.1f}s"

        doc = f"""<!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DLP Scan Report — {html.escape(result.scan_id)}</title>
            {_CSS}
            </head>
            <body>

            <header class="site-header">
            <div class="header-inner">
                <div class="header-title">
                <span class="shield-icon">🛡️</span>
                <div>
                    <h1>DLP Scan Report</h1>
                    <p class="scan-meta">
                    Scan ID: <code>{html.escape(result.scan_id)}</code>
                    &nbsp;·&nbsp;
                    Started: {html.escape(result.scan_started_at.strftime("%Y-%m-%d %H:%M:%S UTC"))}
                    {duration}
                    &nbsp;·&nbsp;
                    Targets: {result.targets_scanned}
                    &nbsp;·&nbsp;
                    Generated: {generated_at}
                    </p>
                </div>
                </div>
                <div class="total-badge {'badge-clean' if total == 0 else 'badge-findings'}">
                {total} finding{"s" if total != 1 else ""}
                </div>
            </div>
            </header>

            <main class="container">

            <!-- ── Summary cards ──────────────────────────────────────────────── -->
            <section class="section">
                <h2 class="section-title">Summary</h2>
                <div class="summary-grid">
                {summary_cards_html}
                </div>
            </section>

            <!-- ── Chart + Framework breakdown ───────────────────────────────── -->
            <section class="section two-col">
                <div class="chart-panel">
                <h2 class="section-title">Severity Distribution</h2>
                {chart_html}
                </div>
                <div class="fw-panel">
                <h2 class="section-title">Compliance Frameworks</h2>
                {framework_html}
                </div>
            </section>

            <!-- ── Findings table ─────────────────────────────────────────────── -->
            <section class="section">
                <div class="table-header-row">
                <h2 class="section-title" style="margin:0">Findings</h2>
                <div class="filter-row">
                    <label for="sev-filter">Filter severity:</label>
                    <select id="sev-filter" onchange="filterTable()">
                    <option value="">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    </select>
                    &nbsp;
                    <label for="search-box">Search:</label>
                    <input id="search-box" type="text" placeholder="rule, file, snippet…"
                        oninput="filterTable()" />
                </div>
                </div>

                {findings_table_html}
            </section>

            <!-- ── Errors ─────────────────────────────────────────────────────── -->
            {"" if not result.errors else _build_errors_section(result.errors)}

            </main>

            <footer class="site-footer">
            <p>Generated by <strong>dlp-scanner</strong> v{html.escape(result.tool_version)}
                &nbsp;·&nbsp; {generated_at}</p>
            </footer>

            {_JS}
            </body>
            </html>"""
        return doc


# ── Private helpers ───────────────────────────────────────────────────────────

def _build_summary_cards(
    total: int,
    by_sev: dict[str, int],
    result: "ScanResult",
) -> str:
    cards = []

    # Total findings card
    cards.append(
        f'<div class="card card-total">'
        f'  <div class="card-value">{total}</div>'
        f'  <div class="card-label">Total Findings</div>'
        f'  <div class="card-sub">{result.targets_scanned} targets scanned</div>'
        f'</div>'
    )

    # One card per severity
    for sev in _SEV_ORDER:
        count = by_sev.get(sev, 0)
        color = _SEV_HEX[sev]
        bg    = _SEV_BG[sev]
        cards.append(
            f'<div class="card" style="border-top:4px solid {color};background:{bg}">'
            f'  <div class="card-value" style="color:{color}">{count}</div>'
            f'  <div class="card-label">{sev.capitalize()}</div>'
            f'</div>'
        )

    return "\n".join(cards)


def _build_donut_chart(by_sev: dict[str, int]) -> str:
    """Render a pure SVG donut chart — zero JavaScript, zero dependencies."""
    total = sum(by_sev.get(s, 0) for s in _SEV_ORDER)
    if total == 0:
        return (
            '<div class="chart-empty">'
            '<span class="check-icon">✅</span>'
            '<p>No findings — scan is clean</p>'
            '</div>'
        )

    cx, cy, r_outer, r_inner = 110, 110, 90, 52
    circumference = 2 * 3.14159265 * r_outer

    # Build arc segments using stroke-dasharray trick on a circle
    # Each segment = (count/total) * circumference
    segments = []
    legend   = []
    offset   = 0.0  # rotate so first slice starts at 12 o'clock (−25% offset)
    gap      = 1.5  # px gap between slices

    for sev in _SEV_ORDER:
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        fraction   = count / total
        arc_length = fraction * circumference - gap
        color      = _SEV_HEX[sev]

        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r_outer}" fill="none"'
            f' stroke="{color}" stroke-width="36"'
            f' stroke-dasharray="{arc_length:.2f} {circumference - arc_length:.2f}"'
            f' stroke-dashoffset="{-offset * circumference / 1 + circumference * 0.25:.2f}"'
            f' style="transition:opacity .2s" />'
        )
        # track offset
        offset += fraction

        pct = fraction * 100
        legend.append(
            f'<li><span class="legend-dot" style="background:{color}"></span>'
            f'{sev.capitalize()} — {count} ({pct:.1f}%)</li>'
        )

    inner_label = (
        f'<text x="{cx}" y="{cy - 8}" text-anchor="middle"'
        f' class="donut-centre-big">{total}</text>'
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle"'
        f' class="donut-centre-small">findings</text>'
    )

    svg = (
        f'<div class="donut-wrap">'
        f'<svg viewBox="0 0 220 220" class="donut-svg" aria-label="Severity donut chart">'
        f'  <circle cx="{cx}" cy="{cy}" r="{r_outer}" fill="none"'
        f'          stroke="#f0f0f0" stroke-width="36"/>'
        + "".join(segments)
        + f'  <circle cx="{cx}" cy="{cy}" r="{r_inner}" fill="white"/>'
        + inner_label
        + f'</svg>'
        f'<ul class="legend">{"".join(legend)}</ul>'
        f'</div>'
    )
    return svg


def _build_framework_table(by_fw: dict[str, int]) -> str:
    if not by_fw:
        return '<p class="muted">No compliance frameworks triggered.</p>'

    rows = []
    max_count = max(by_fw.values())
    for fw, count in sorted(by_fw.items(), key=lambda x: -x[1]):
        bar_pct = int(count / max_count * 100)
        rows.append(
            f'<tr>'
            f'  <td><span class="fw-badge">{html.escape(fw)}</span></td>'
            f'  <td class="fw-count">{count}</td>'
            f'  <td class="fw-bar-cell">'
            f'    <div class="fw-bar" style="width:{bar_pct}%"></div>'
            f'  </td>'
            f'</tr>'
        )

    return (
        f'<table class="fw-table">'
        f'  <thead><tr><th>Framework</th><th>Findings</th><th></th></tr></thead>'
        f'  <tbody>{"".join(rows)}</tbody>'
        f'</table>'
    )


def _build_findings_table(findings: "list[Finding]") -> str:
    if not findings:
        return (
            '<div class="no-findings">'
            '<span class="check-icon">✅</span>'
            '<p>No findings detected. This scan is clean.</p>'
            '</div>'
        )

    rows = []
    for i, f in enumerate(findings):
        sev   = f.severity.lower()
        color = _SEV_HEX.get(sev, "#888")
        bg    = _SEV_BG.get(sev, "#fff")

        loc = html.escape(f.location.uri)
        if f.location.line is not None:
            loc += f":{f.location.line}"
        if f.location.table_name:
            loc += f" [{html.escape(f.location.table_name)}]"

        snippet = f.redacted_snippet
        if len(snippet) > _SNIPPET_MAX:
            snippet = snippet[:_SNIPPET_MAX] + "…"
        snippet_escaped = html.escape(snippet)

        frameworks = ", ".join(html.escape(fw) for fw in f.compliance_frameworks)
        conf_pct   = f"{f.confidence:.0%}"

        rows.append(
            f'<tr data-severity="{sev}" style="background:{bg}">'
            f'  <td><span class="sev-badge" style="background:{color};color:#fff">'
            f'        {html.escape(sev.upper())}</span></td>'
            f'  <td title="{html.escape(f.rule_id)}">{html.escape(f.rule_name)}</td>'
            f'  <td class="mono-cell">{loc}</td>'
            f'  <td class="conf-cell">'
            f'    <div class="conf-bar-wrap">'
            f'      <div class="conf-bar" style="width:{conf_pct};background:{color}"></div>'
            f'    </div>'
            f'    <span class="conf-label">{conf_pct}</span>'
            f'  </td>'
            f'  <td class="mono-cell snippet-cell" title="{html.escape(f.redacted_snippet)}">'
            f'    {snippet_escaped}</td>'
            f'  <td>{frameworks}</td>'
            f'  <td class="muted small-text">'
            f'    {html.escape(f.detected_at.strftime("%H:%M:%S"))}</td>'
            f'</tr>'
        )

    return (
        f'<div class="table-wrap">'
        f'<table id="findings-table" class="findings-table">'
        f'  <thead>'
        f'    <tr>'
        f'      <th data-col="0" onclick="sortTable(0)" class="sortable">Severity <span class="sort-icon">⇅</span></th>'
        f'      <th data-col="1" onclick="sortTable(1)" class="sortable">Rule <span class="sort-icon">⇅</span></th>'
        f'      <th data-col="2" onclick="sortTable(2)" class="sortable">Location <span class="sort-icon">⇅</span></th>'
        f'      <th data-col="3" onclick="sortTable(3)" class="sortable">Confidence <span class="sort-icon">⇅</span></th>'
        f'      <th>Snippet</th>'
        f'      <th data-col="5" onclick="sortTable(5)" class="sortable">Frameworks <span class="sort-icon">⇅</span></th>'
        f'      <th data-col="6" onclick="sortTable(6)" class="sortable">Time <span class="sort-icon">⇅</span></th>'
        f'    </tr>'
        f'  </thead>'
        f'  <tbody>{"".join(rows)}</tbody>'
        f'</table>'
        f'</div>'
        f'<p class="table-count" id="row-count">'
        f'  Showing {len(findings)} of {len(findings)} findings</p>'
    )


def _build_errors_section(errors: list[str]) -> str:
    items = "\n".join(
        f'<li><code>{html.escape(e)}</code></li>' for e in errors
    )
    return (
        f'<section class="section">'
        f'  <h2 class="section-title" style="color:#c0392b">Scan Errors</h2>'
        f'  <ul class="error-list">{items}</ul>'
        f'</section>'
    )


# ── Inline CSS ────────────────────────────────────────────────────────────────

_CSS = """<style>
/* ── Reset & base ─────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               Helvetica, Arial, sans-serif;
  background: #f5f7fa;
  color: #2c3e50;
  font-size: 14px;
  line-height: 1.5;
}
code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
       font-size: 0.88em; }

/* ── Layout ───────────────────────────────────────────────── */
.container { max-width: 1280px; margin: 0 auto; padding: 24px 20px 48px; }
.section   { background: #fff; border-radius: 8px; padding: 24px;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 20px; }
.section-title { font-size: 1rem; font-weight: 700; color: #34495e;
                 margin-bottom: 16px; text-transform: uppercase;
                 letter-spacing: .04em; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
           background: transparent; box-shadow: none; padding: 0; }
.two-col > .chart-panel,
.two-col > .fw-panel   { background: #fff; border-radius: 8px;
                          padding: 24px;
                          box-shadow: 0 1px 4px rgba(0,0,0,.08); }

/* ── Header ───────────────────────────────────────────────── */
.site-header { background: #1a252f; color: #ecf0f1; padding: 20px 0; }
.header-inner{ max-width:1280px; margin:0 auto; padding:0 20px;
               display:flex; align-items:center; justify-content:space-between;
               gap:16px; flex-wrap:wrap; }
.header-title { display:flex; align-items:center; gap:14px; }
.shield-icon  { font-size: 2.2rem; }
h1 { font-size: 1.4rem; font-weight: 700; }
.scan-meta { font-size: .78rem; color: #95a5a6; margin-top: 3px; }
.scan-meta code { color:#a9cce3; }
.total-badge { padding: 8px 18px; border-radius: 20px; font-weight: 700;
               font-size: 1rem; white-space: nowrap; }
.badge-findings { background: #c0392b; color: #fff; }
.badge-clean    { background: #27ae60; color: #fff; }

/* ── Summary cards ────────────────────────────────────────── */
.summary-grid { display: grid;
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 14px; }
.card { background: #f8f9fa; border-radius: 8px; padding: 18px 14px;
        text-align: center; border-top: 4px solid #bdc3c7; }
.card-total { border-top-color: #2c3e50; background: #f0f3f4; }
.card-value { font-size: 2rem; font-weight: 800; line-height: 1; }
.card-label { font-size: .8rem; font-weight: 600; text-transform: uppercase;
              letter-spacing: .05em; color: #7f8c8d; margin-top: 6px; }
.card-sub   { font-size: .72rem; color: #95a5a6; margin-top: 4px; }

/* ── Donut chart ──────────────────────────────────────────── */
.donut-wrap { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
.donut-svg  { width: 180px; height: 180px; flex-shrink: 0;
              transform: rotate(-90deg); }
.donut-centre-big   { font-size: 28px; font-weight: 800; fill: #2c3e50;
                       transform: rotate(90deg);
                       transform-origin: 110px 110px; }
.donut-centre-small { font-size: 11px; fill: #7f8c8d;
                       transform: rotate(90deg);
                       transform-origin: 110px 110px; }
.legend     { list-style: none; }
.legend li  { display: flex; align-items: center; gap: 8px;
              margin-bottom: 8px; font-size: .85rem; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%;
              flex-shrink: 0; }
.chart-empty, .no-findings { text-align: center; padding: 32px;
                              color: #7f8c8d; }
.check-icon { font-size: 2.5rem; display: block; margin-bottom: 10px; }

/* ── Framework table ──────────────────────────────────────── */
.fw-table   { width: 100%; border-collapse: collapse; }
.fw-table th{ text-align: left; font-size: .75rem; color: #7f8c8d;
              text-transform: uppercase; letter-spacing: .04em;
              padding: 4px 8px 8px; border-bottom: 2px solid #ecf0f1; }
.fw-table td{ padding: 8px; border-bottom: 1px solid #ecf0f1;
              vertical-align: middle; }
.fw-badge   { background: #eaf2ff; color: #2980b9; font-size: .78rem;
              font-weight: 700; padding: 2px 8px; border-radius: 4px;
              white-space: nowrap; }
.fw-count   { font-weight: 700; width: 50px; text-align: right; }
.fw-bar-cell{ width: 120px; }
.fw-bar     { height: 10px; background: #3498db; border-radius: 5px;
              transition: width .3s; min-width: 4px; }

/* ── Findings table ───────────────────────────────────────── */
.table-header-row { display:flex; align-items:center;
                    justify-content:space-between;
                    flex-wrap:wrap; gap:12px; margin-bottom:16px; }
.filter-row  { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.filter-row select, .filter-row input {
  border: 1px solid #dfe6e9; border-radius: 5px;
  padding: 5px 10px; font-size: .83rem; background: #f8f9fa;
  color: #2c3e50; outline: none; }
.filter-row input { width: 200px; }
.filter-row select:focus, .filter-row input:focus {
  border-color: #3498db; background: #fff; }

.table-wrap { overflow-x: auto; }
.findings-table { width: 100%; border-collapse: collapse;
                  table-layout: fixed; }
.findings-table th { background: #2c3e50; color: #ecf0f1; padding: 10px 12px;
                      text-align: left; font-size: .78rem;
                      text-transform: uppercase; letter-spacing: .04em;
                      position: sticky; top: 0; z-index: 1;
                      white-space: nowrap; }
.findings-table th:nth-child(1) { width:  90px; }
.findings-table th:nth-child(2) { width: 180px; }
.findings-table th:nth-child(3) { width: 200px; }
.findings-table th:nth-child(4) { width: 110px; }
.findings-table th:nth-child(5) { width: 200px; }
.findings-table th:nth-child(6) { width: 130px; }
.findings-table th:nth-child(7) { width:  80px; }

.findings-table td { padding: 9px 12px; border-bottom: 1px solid #ecf0f1;
                      vertical-align: middle; overflow: hidden;
                      text-overflow: ellipsis; white-space: nowrap; }
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover td { filter: brightness(.96); }

.sortable      { cursor: pointer; user-select: none; }
.sortable:hover{ background: #34495e; }
.sort-icon     { opacity: .5; margin-left: 4px; }
th.sort-asc  .sort-icon { opacity:1; content:"↑"; }
th.sort-desc .sort-icon { opacity:1; content:"↓"; }

.sev-badge  { display: inline-block; padding: 2px 8px; border-radius: 4px;
              font-size: .72rem; font-weight: 800; letter-spacing: .04em; }

.conf-cell  { white-space: nowrap; }
.conf-bar-wrap { background: #ecf0f1; border-radius: 4px; height: 6px;
                 margin-bottom: 4px; }
.conf-bar   { height: 6px; border-radius: 4px; transition: width .2s; }
.conf-label { font-size: .75rem; font-weight: 600; }

.mono-cell   { font-family: "SFMono-Regular", Consolas, monospace;
               font-size: .80rem; }
.snippet-cell{ cursor: default; }

.table-count { font-size: .78rem; color: #7f8c8d; margin-top: 10px;
               text-align: right; }
.muted       { color: #95a5a6; }
.small-text  { font-size: .78rem; }

/* ── Error list ───────────────────────────────────────────── */
.error-list { list-style: none; }
.error-list li { padding: 8px 12px; background: #fdecea;
                 border-left: 4px solid #c0392b; border-radius: 4px;
                 margin-bottom: 6px; font-size: .85rem; color: #922b21; }

/* ── Footer ───────────────────────────────────────────────── */
.site-footer { text-align: center; padding: 20px; font-size: .78rem;
               color: #95a5a6; }

/* ── Responsive ───────────────────────────────────────────── */
@media (max-width: 768px) {
  .two-col { grid-template-columns: 1fr; }
  .donut-svg { width: 140px; height: 140px; }
}
</style>"""


# ── Inline JavaScript ─────────────────────────────────────────────────────────

_JS = """<script>
// ── Sort state ────────────────────────────────────────────────────────────
const _sortState = { col: null, dir: 1 };

function sortTable(colIdx) {
  const table = document.getElementById('findings-table');
  const tbody = table.tBodies[0];
  const ths   = table.tHead.rows[0].cells;
  const rows  = Array.from(tbody.rows);

  // Toggle direction if same column
  if (_sortState.col === colIdx) {
    _sortState.dir *= -1;
  } else {
    _sortState.col = colIdx;
    _sortState.dir = 1;
  }

  // Update header icons
  for (const th of ths) {
    th.classList.remove('sort-asc', 'sort-desc');
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.textContent = '⇅';
  }
  const activeHeader = ths[colIdx];
  if (activeHeader) {
    const cls  = _sortState.dir === 1 ? 'sort-asc' : 'sort-desc';
    activeHeader.classList.add(cls);
    const icon = activeHeader.querySelector('.sort-icon');
    if (icon) icon.textContent = _sortState.dir === 1 ? '↑' : '↓';
  }

  // Severity sort order for the severity column (col 0)
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  rows.sort((a, b) => {
    const aText = (a.cells[colIdx]?.textContent || '').trim().toLowerCase();
    const bText = (b.cells[colIdx]?.textContent || '').trim().toLowerCase();

    if (colIdx === 0) {
      // Sort by semantic severity order, not alphabetically
      const aO = SEV_ORDER[a.dataset.severity] ?? 99;
      const bO = SEV_ORDER[b.dataset.severity] ?? 99;
      return (aO - bO) * _sortState.dir;
    }
    if (colIdx === 3) {
      // Confidence — strip % and sort numerically
      const aNum = parseFloat(aText) || 0;
      const bNum = parseFloat(bText) || 0;
      return (aNum - bNum) * _sortState.dir;
    }
    // Default: lexicographic
    return aText.localeCompare(bText) * _sortState.dir;
  });

  rows.forEach(r => tbody.appendChild(r));
  updateRowCount();
}

// ── Filter ────────────────────────────────────────────────────────────────
function filterTable() {
  const sevFilter  = document.getElementById('sev-filter').value.toLowerCase();
  const searchText = document.getElementById('search-box').value.toLowerCase();
  const tbody = document.getElementById('findings-table').tBodies[0];
  let visible = 0;

  for (const row of tbody.rows) {
    const sev     = row.dataset.severity || '';
    const rowText = row.textContent.toLowerCase();

    const sevOk    = !sevFilter  || sev === sevFilter;
    const searchOk = !searchText || rowText.includes(searchText);

    const show = sevOk && searchOk;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  }
  updateRowCount(visible);
}

function updateRowCount(count) {
  const tbody = document.getElementById('findings-table').tBodies[0];
  const total = tbody.rows.length;
  const shown = count ?? total;
  const el = document.getElementById('row-count');
  if (el) el.textContent = `Showing ${shown} of ${total} findings`;
}

// Initial count
document.addEventListener('DOMContentLoaded', () => updateRowCount());
</script>"""