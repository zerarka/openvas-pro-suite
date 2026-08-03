import os
import pandas as pd
from datetime import datetime

def generate_executive_html_report(active_csv_paths, output_html_path, risk_df=None, master_targets_df=None, fp_df=None, detailed_df=None):
    """
    Generates a standalone, beautiful HTML Executive Security Summary Report
    with dark modern styling, line numbers, threat intelligence metrics (CISA KEV / EPSS),
    host risk breakdown, and detailed vulnerability listings.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_scans = len(active_csv_paths)
    total_hosts = len(risk_df) if risk_df is not None and not risk_df.empty else 0
    top_host = risk_df.iloc[0]['Hostname'] if total_hosts > 0 and 'Hostname' in risk_df.columns else 'N/A'
    top_risk_score = risk_df.iloc[0]['Risk Score'] if total_hosts > 0 and 'Risk Score' in risk_df.columns else 0

    master_count = len(master_targets_df) if master_targets_df is not None and not master_targets_df.empty else 0
    fp_count = len(fp_df) if fp_df is not None and not fp_df.empty else 0

    kev_count = 0
    high_epss_count = 0
    if detailed_df is not None and not detailed_df.empty:
        if 'CISA KEV' in detailed_df.columns:
            kev_count = detailed_df['CISA KEV'].sum()
        if 'EPSS Score' in detailed_df.columns:
            high_epss_count = (detailed_df['EPSS Score'] > 0.1).sum()

    # 1. Build Host Risk Score Table HTML (with Line #)
    risk_table_html = ""
    if risk_df is not None and not risk_df.empty:
        rows = ""
        for idx, row in enumerate(risk_df.head(15).to_dict('records'), start=1):
            score = round(row.get('Risk Score', 0), 1)
            badge_class = "badge-crit" if score >= 25 else ("badge-high" if score >= 10 else ("badge-med" if score >= 4 else "badge-low"))
            rows += f"""
            <tr>
                <td style="color: #94a3b8; font-weight: bold; width: 40px;">#{idx}</td>
                <td><strong>{row.get('Hostname', 'Unknown')}</strong></td>
                <td><span class="{badge_class}">{score}</span></td>
            </tr>
            """
        risk_table_html = f"""
        <table class="report-table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th>Hostname / IP Address</th>
                    <th>Aggregated Risk Score</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """
    else:
        risk_table_html = "<p>No risk score data available.</p>"

    # 2. Build Master Targets Table HTML (with Line #)
    master_table_html = ""
    if master_targets_df is not None and not master_targets_df.empty:
        rows = ""
        for idx, row in enumerate(master_targets_df.head(10).to_dict('records'), start=1):
            rows += f"""
            <tr>
                <td style="color: #94a3b8; font-weight: bold; width: 40px;">#{idx}</td>
                <td><strong>{row.get('NVT Name', 'N/A')}</strong></td>
                <td>{row.get('Severity', 'N/A')}</td>
                <td><span class="badge-subnets">{row.get('Subnets Spanned', 1)} Subnets</span></td>
                <td>{row.get('Total Hosts Affected', 1)} Hosts</td>
            </tr>
            """
        master_table_html = f"""
        <table class="report-table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th>Vulnerability (NVT Name)</th>
                    <th>Severity</th>
                    <th>Subnets Spanned</th>
                    <th>Total Hosts Affected</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """
    else:
        master_table_html = "<p>No cross-VLAN master targets detected.</p>"

    # 3. Build Detailed Vulnerabilities Table HTML (with Line #, CISA KEV & EPSS)
    detailed_table_html = ""
    if detailed_df is not None and not detailed_df.empty:
        rows = ""
        top_vulns = detailed_df.head(20).to_dict('records')
        for idx, row in enumerate(top_vulns, start=1):
            host = row.get('Hostname', 'N/A')
            nvt = row.get('NVT Name', 'N/A')
            sev = row.get('Severity', 'N/A')
            cisa = "🚨 YES (Exploited)" if row.get('CISA KEV', False) else "No"
            epss_val = float(row.get('EPSS Score', 0.0))
            epss_pct = f"{epss_val * 100:.1f}%"
            port = row.get('Port', 'N/A')
            cisa_class = "badge-crit" if row.get('CISA KEV', False) else "badge-low"
            
            rows += f"""
            <tr>
                <td style="color: #94a3b8; font-weight: bold; width: 40px;">#{idx}</td>
                <td><strong>{host}</strong></td>
                <td>{nvt}</td>
                <td>{port}</td>
                <td><span class="badge-med">{sev}</span></td>
                <td><span class="{cisa_class}">{cisa}</span></td>
                <td><strong>{epss_pct}</strong></td>
            </tr>
            """
        detailed_table_html = f"""
        <table class="report-table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th>Target Host</th>
                    <th>Vulnerability Name</th>
                    <th>Port</th>
                    <th>Severity</th>
                    <th>CISA KEV</th>
                    <th>EPSS Probability</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """
    else:
        detailed_table_html = "<p>No detailed vulnerability data loaded.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OpenVAS Executive Vulnerability Summary Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #1e293b;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }}
        .header {{
            border-bottom: 2px solid #334155;
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            margin: 0;
            color: #38bdf8;
            font-size: 28px;
        }}
        .header .meta {{
            color: #94a3b8;
            font-size: 14px;
        }}
        .grid-cards {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 35px;
        }}
        .card {{
            background: #334155;
            padding: 18px;
            border-radius: 12px;
            text-align: center;
        }}
        .card .val {{
            font-size: 28px;
            font-weight: bold;
            color: #38bdf8;
            margin-top: 5px;
        }}
        .card .lbl {{
            font-size: 11px;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        h2 {{
            color: #f1f5f9;
            font-size: 20px;
            margin-top: 35px;
            border-left: 4px solid #38bdf8;
            padding-left: 12px;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .report-table th, .report-table td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        .report-table th {{
            background-color: #0f172a;
            color: #94a3b8;
            font-weight: 600;
        }}
        .badge-crit {{ background: #ef4444; color: #fff; padding: 3px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }}
        .badge-high {{ background: #f97316; color: #fff; padding: 3px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }}
        .badge-med {{ background: #eab308; color: #000; padding: 3px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }}
        .badge-low {{ background: #22c55e; color: #fff; padding: 3px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }}
        .badge-subnets {{ background: #0284c7; color: #fff; padding: 3px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #334155;
            color: #64748b;
            font-size: 12px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ Executive Vulnerability Summary</h1>
                <div class="meta">OpenVAS Pro Suite v4.0 Risk-Based Threat Intelligence Report</div>
            </div>
            <div class="meta">Generated: {now_str}</div>
        </div>

        <div class="grid-cards">
            <div class="card">
                <div class="lbl">Active Scans</div>
                <div class="val">{total_scans}</div>
            </div>
            <div class="card">
                <div class="lbl">Discovered Assets</div>
                <div class="val">{total_hosts}</div>
            </div>
            <div class="card">
                <div class="lbl">Top Risk Host</div>
                <div class="val" style="font-size: 16px; word-break: break-all;">{top_host}</div>
            </div>
            <div class="card">
                <div class="lbl">CISA KEV Exploited</div>
                <div class="val" style="color: #ef4444;">{kev_count}</div>
            </div>
            <div class="card">
                <div class="lbl">High EPSS (&gt;10%)</div>
                <div class="val" style="color: #f97316;">{high_epss_count}</div>
            </div>
        </div>

        <h2>Highest Risk Assets Summary</h2>
        {risk_table_html}

        <h2>Top 20 Priority Vulnerabilities (Threat Intelligence & Line #)</h2>
        {detailed_table_html}

        <h2>Cross-VLAN Master Targets (Infrastructure Impact)</h2>
        {master_table_html}

        <div class="footer">
            Generated automatically by OpenVAS Pro Suite v4.0 | Threat-Informed Risk Analytics Engine
        </div>
    </div>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_html_path) or '.', exist_ok=True)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_html_path
