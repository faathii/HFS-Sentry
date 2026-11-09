"""Executive HTML Report Generator for HFS-Sentry.

Zero external dependencies (pure standard Python 3).
Generates self-contained, responsive, dark/cyber styled audit reports.
"""

from datetime import datetime, timezone
import html as html_lib
import json
from typing import Any, Dict, List, Optional


def _render_svg_gauge(score: int, label: str = "SCORE") -> str:
    """Generate inline native SVG circular progress gauge without external libraries."""
    clamped_score = max(0, min(100, score))
    # Circle perimeter for r=54 is 2 * pi * 54 = 339.29
    perimeter = 339.29
    dash_offset = perimeter * (1.0 - (clamped_score / 100.0))
    stroke_color = "#00e676" if clamped_score >= 85 else ("#ffd600" if clamped_score >= 70 else "#ff5252")

    return f"""
    <div style="display: flex; align-items: center; justify-content: center; margin-bottom: 24px;">
        <svg width="160" height="160" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r="54" fill="none" stroke="#1c2f4c" stroke-width="12" />
            <circle cx="70" cy="70" r="54" fill="none" stroke="{stroke_color}" stroke-width="12"
                    stroke-dasharray="{perimeter}" stroke-dashoffset="{dash_offset}"
                    stroke-linecap="round" transform="rotate(-90 70 70)"
                    style="transition: stroke-dashoffset 1s ease-in-out;" />
            <text x="70" y="65" text-anchor="middle" fill="#ffffff" font-size="28" font-weight="bold" font-family="-apple-system, sans-serif">{clamped_score}</text>
            <text x="70" y="86" text-anchor="middle" fill="{stroke_color}" font-size="12" font-weight="bold" letter-spacing="1" font-family="-apple-system, sans-serif">{label}</text>
        </svg>
    </div>
    """


def generate_html_report(data: Dict[str, Any], title: Optional[str] = None) -> str:
    """Generate self-contained HTML audit report from analysis dictionary."""
    tool_name = data.get("tool", "HFS-Sentry Diagnostic")
    report_title = title or f"{tool_name} — Executive Security Audit Report"
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # SVG Gauge if score or grade present
    gauge_html = ""
    if "security_score" in data:
        score_val = data["security_score"]
        label_val = data.get("grade", "SCORE")
        gauge_html = _render_svg_gauge(score_val, label=f"GRADO {label_val}")
    elif "score_fraction" in data:
        # e.g. "5/6"
        parts = str(data["score_fraction"]).split("/")
        if len(parts) == 2 and parts[1].isdigit():
            frac_score = int(int(parts[0]) / int(parts[1]) * 100)
            gauge_html = _render_svg_gauge(frac_score, label=f"OWASP {data.get('grade', '')}")

    # Render key-value metadata rows
    meta_rows = []
    for k, v in data.items():
        if isinstance(v, (str, int, float, bool)) and k not in ("tool",):
            formatted_key = html_lib.escape(k.replace("_", " ").title())
            escaped_v = html_lib.escape(str(v))
            meta_rows.append(f"""
                <div class="meta-item">
                    <span class="meta-label">{formatted_key}</span>
                    <span class="meta-value">{escaped_v}</span>
                </div>
            """)

    # Render tables if list of dicts present
    table_sections = []
    for idx, (k, v) in enumerate(data.items()):
        if isinstance(v, list) and v and isinstance(v[0], dict):
            table_title = k.replace("_", " ").title()
            table_id = f"table_{idx}"
            headers = list(v[0].keys())
            header_html = "".join(f"<th>{h.replace('_', ' ').upper()}</th>" for h in headers)

            rows_html = []
            for item in v:
                cells = []
                for h in headers:
                    val = item.get(h, "")
                    if isinstance(val, list):
                        val = ", ".join(str(x) for x in val)
                    val_str = str(val)
                    cell_class = ""
                    if any(term in val_str.lower() for term in ("crit", "fail", "risk", "high", "modifi")):
                        cell_class = "danger"
                    elif any(term in val_str.lower() for term in ("pass", "clean", "ok", "healthy", "open")):
                        cell_class = "success"
                    elif any(term in val_str.lower() for term in ("warn", "notice", "medium")):
                        cell_class = "warning"

                    cells.append(f'<td class="{cell_class}">{html_lib.escape(val_str)}</td>')
                rows_html.append(f"<tr>{''.join(cells)}</tr>")

            table_sections.append(f"""
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 14px;">
                        <h3 class="card-title" style="margin: 0; border: none; padding: 0;">{table_title} ({len(v)} entries)</h3>
                        <input type="text" class="search-box" placeholder="🔍 Filtrar registros..." onkeyup="filterReportTable(this, '{table_id}')">
                    </div>
                    <div class="table-container">
                        <table id="{table_id}">
                            <thead><tr>{header_html}</tr></thead>
                            <tbody>{''.join(rows_html)}</tbody>
                        </table>
                    </div>
                </div>
            """)

    # Raw JSON collapsible snippet
    json_snippet = html_lib.escape(json.dumps(data, indent=2, ensure_ascii=False))

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        :root {{
            --bg-dark: #0a111e;
            --bg-card: #121d30;
            --surface: #1e314f;
            --border: #274268;
            --accent-cyan: #00d2ff;
            --accent-blue: #2979ff;
            --accent-green: #00e676;
            --accent-red: #ff5252;
            --accent-yellow: #ffd600;
            --text-primary: #ffffff;
            --text-secondary: #9fb3c8;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            background: linear-gradient(135deg, #121d30 0%, #1e314f 100%);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 28px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }}
        .header h1 {{
            color: var(--accent-cyan);
            font-size: 24px;
            margin-bottom: 6px;
        }}
        .header p {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .badge {{
            background: var(--surface);
            color: var(--accent-green);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
            border: 1px solid var(--border);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}
        .meta-item {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
        }}
        .meta-label {{
            display: block;
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .meta-value {{
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{
            color: var(--accent-cyan);
            font-size: 18px;
            margin-bottom: 14px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        .table-container {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: var(--surface);
            color: var(--accent-cyan);
            padding: 10px 12px;
            font-weight: bold;
            border-bottom: 2px solid var(--border);
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }}
        tr:hover td {{
            background: rgba(0, 210, 255, 0.05);
        }}
        td.danger {{ color: var(--accent-red); font-weight: bold; }}
        td.success {{ color: var(--accent-green); font-weight: bold; }}
        td.warning {{ color: var(--accent-yellow); font-weight: bold; }}
        pre {{
            background: #050911;
            color: #40c4ff;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: Consolas, Monaco, monospace;
            font-size: 12px;
        }}
        footer {{
            margin-top: 32px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 13px;
            padding: 16px;
            border-top: 1px solid var(--border);
        }}
        .btn-print {{
            background: linear-gradient(135deg, #00d2ff, #2979ff);
            color: #ffffff;
            border: none;
            padding: 8px 18px;
            font-size: 13px;
            font-weight: bold;
            border-radius: 6px;
            cursor: pointer;
            transition: opacity 0.2s;
            margin-right: 12px;
        }}
        .btn-print:hover {{ opacity: 0.9; }}
        .search-box {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            width: 220px;
        }}
        .search-box:focus {{
            outline: none;
            border-color: var(--accent-cyan);
        }}
        @media print {{
            body {{
                background: #ffffff !important;
                color: #111827 !important;
                padding: 0 !important;
            }}
            .header {{
                border-bottom: 2px solid #374151 !important;
            }}
            .header h1 {{
                color: #111827 !important;
            }}
            .card, .meta-item {{
                background: #ffffff !important;
                border: 1px solid #d1d5db !important;
                color: #111827 !important;
                page-break-inside: avoid;
            }}
            .card-title, .meta-label, th {{
                color: #1f2937 !important;
                background: #f3f4f6 !important;
            }}
            td {{
                color: #111827 !important;
                border-bottom: 1px solid #e5e7eb !important;
            }}
            .btn-print, .search-box {{
                display: none !important;
            }}
            .badge {{
                border: 1px solid #9ca3af !important;
                color: #111827 !important;
                background: #f3f4f6 !important;
            }}
            pre {{
                background: #f8fafc !important;
                color: #1e293b !important;
                border: 1px solid #e2e8f0 !important;
            }}
        }}
    </style>
    <script>
    function filterReportTable(input, tableId) {{
        var filter = input.value.toLowerCase();
        var table = document.getElementById(tableId);
        if (!table) return;
        var trs = table.getElementsByTagName("tr");
        for (var i = 1; i < trs.length; i++) {{
            var rowText = trs[i].textContent.toLowerCase();
            trs[i].style.display = rowText.indexOf(filter) > -1 ? "" : "none";
        }}
    }}
    </script>
</head>
<body>
    <div class="header">
        <div>
            <h1>{report_title}</h1>
            <p>Generado automáticamente por HFS-Sentry Suite &bull; {generated_at}</p>
        </div>
        <div style="display: flex; align-items: center;">
            <button onclick="window.print()" class="btn-print">🖨️ Imprimir / Guardar como PDF</button>
            <div class="badge">AUDITADO POR HFS-SENTRY</div>
        </div>
    </div>

    {gauge_html}

    <div class="meta-grid">
        {''.join(meta_rows)}
    </div>

    {''.join(table_sections)}

    <div class="card">
        <h3 class="card-title">Dataset Criptográfico Estructurado (JSON)</h3>
        <pre><code>{json_snippet}</code></pre>
    </div>

    <footer>
        HFS-Sentry Suite &bull; Autor: Hamza El Fathi Sofyani &bull; Código Libre (Licencia MIT)
    </footer>
</body>
</html>
"""
    return html

