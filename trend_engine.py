import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Tuple

SEVERITY_WEIGHTS = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 1,
    'Log': 0
}

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.loc[:, ~df.columns.duplicated()].copy()
    col_map = {}
    cols_lower = {str(col).strip().lower(): col for col in df.columns}

    target_host = None
    for cand in ['ip', 'hostname', 'host', 'target']:
        if cand in cols_lower:
            target_host = cols_lower[cand]
            break
    if target_host:
        col_map[target_host] = 'Hostname'

    target_sev = None
    for cand in ['severity', 'threat', 'cvss_severity', 'cvss']:
        if cand in cols_lower:
            target_sev = cols_lower[cand]
            break
    if target_sev and target_sev != target_host:
        col_map[target_sev] = 'Severity'

    target_nvt = None
    for cand in ['nvt name', 'nvt', 'vulnerability', 'vulnerability name', 'name']:
        if cand in cols_lower:
            target_nvt = cols_lower[cand]
            break
    if target_nvt and target_nvt not in [target_host, target_sev]:
        col_map[target_nvt] = 'NVT Name'

    res = df.rename(columns=col_map)
    return res.loc[:, ~res.columns.duplicated()].copy()

def aggregate_report_series(csv_paths: List[str], fp_filter_fn=None, progress_callback=None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Reads up to N CSV report paths, computes per-host risk scores per report."""
    report_data = []

    total_files = len(csv_paths)
    for idx, path in enumerate(csv_paths):
        filename = os.path.basename(path)
        label = f"R{idx+1}: {filename[:15]}"

        if progress_callback and callable(progress_callback):
            progress_callback(idx + 1, total_files, f"Processing {filename}...")

        try:
            df = pd.read_csv(path)
            df = normalize_columns(df)
            
            if fp_filter_fn and callable(fp_filter_fn):
                df = fp_filter_fn(df)

            if 'Hostname' not in df.columns or 'Severity' not in df.columns:
                continue

            df['Weight'] = df['Severity'].astype(str).str.capitalize().map(SEVERITY_WEIGHTS).fillna(0)
            scores = df.groupby('Hostname')['Weight'].sum().reset_index()
            scores['Report'] = label
            scores['Report_Idx'] = idx + 1
            report_data.append(scores)
        except Exception as e:
            print(f"[Trend Engine Error] Failed processing {path}: {e}")

    if not report_data:
        return pd.DataFrame(), pd.DataFrame()

    combined = pd.concat(report_data, ignore_index=True)
    pivot_df = combined.pivot(index='Hostname', columns='Report', values='Weight').fillna(0)

    summary_list = []
    for host in pivot_df.index:
        vals = pivot_df.loc[host].values
        if len(vals) >= 2:
            delta = vals[-1] - vals[0]
            if delta > 0:
                trend = f"🔴 Rising (+{delta:.1f})"
            elif delta < 0:
                trend = f"🟢 Falling ({delta:.1f})"
            else:
                trend = "🟡 Stable"
        else:
            trend = "⚪ Single Scan"

        summary_list.append({
            'Hostname': host,
            'Latest Risk Score': vals[-1] if len(vals) > 0 else 0,
            'Initial Risk Score': vals[0] if len(vals) > 0 else 0,
            'Max Risk Score': np.max(vals) if len(vals) > 0 else 0,
            'Trend': trend
        })

    summary_df = pd.DataFrame(summary_list).sort_values(by='Latest Risk Score', ascending=False)
    return pivot_df, summary_df

def generate_heatmap_figure(pivot_df: pd.DataFrame) -> matplotlib.figure.Figure:
    """Generates a Seaborn / Matplotlib heatmap Figure for embedding in Tkinter."""
    fig, ax = plt.subplots(figsize=(8, 5), dpi=100)
    fig.patch.set_facecolor('#f5f5f7')
    ax.set_facecolor('#ffffff')

    if pivot_df.empty:
        ax.text(0.5, 0.5, "No report data loaded for heatmap", ha='center', va='center', fontsize=12)
        ax.axis('off')
        return fig

    sns.heatmap(
        pivot_df,
        annot=True,
        fmt=".0f",
        cmap="YlOrRd",
        linewidths=0.5,
        cbar_kws={'label': 'Risk Score'},
        ax=ax
    )
    ax.set_title("Vulnerability Risk Score Heatmap (Host vs Scan Series)", fontsize=12, fontweight='bold', pad=12)
    ax.set_xlabel("Scan Reports", fontsize=10, labelpad=8)
    ax.set_ylabel("Hostnames / IPs", fontsize=10, labelpad=8)
    plt.xticks(rotation=30, ha='right', fontsize=8)
    plt.yticks(rotation=0, fontsize=8)
    fig.tight_layout()
    return fig

def generate_trend_line_figure(pivot_df: pd.DataFrame, hostname: str) -> matplotlib.figure.Figure:
    """Generates a trend line chart for a specific host."""
    fig, ax = plt.subplots(figsize=(8, 4), dpi=100)
    fig.patch.set_facecolor('#f5f5f7')
    ax.set_facecolor('#ffffff')

    if pivot_df.empty or hostname not in pivot_df.index:
        ax.text(0.5, 0.5, f"No trend data available for host: {hostname}", ha='center', va='center', fontsize=12)
        ax.axis('off')
        return fig

    series = pivot_df.loc[hostname]
    x_labels = series.index.tolist()
    y_values = series.values

    ax.plot(x_labels, y_values, marker='o', color='#e74c3c', linewidth=2.5, markersize=8, label=hostname)
    
    if len(y_values) >= 2:
        x_numeric = np.arange(len(y_values))
        z = np.polyfit(x_numeric, y_values, 1)
        p = np.poly1d(z)
        ax.plot(x_labels, p(x_numeric), "--", color="#34495e", alpha=0.7, label="Linear Trend")

    ax.set_title(f"Risk Score Trajectory for {hostname}", fontsize=12, fontweight='bold', pad=12)
    ax.set_xlabel("Scan Reports", fontsize=10, labelpad=8)
    ax.set_ylabel("Aggregated Risk Score", fontsize=10, labelpad=8)
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.legend(loc='upper right')
    plt.xticks(rotation=30, ha='right', fontsize=8)
    fig.tight_layout()
    return fig
