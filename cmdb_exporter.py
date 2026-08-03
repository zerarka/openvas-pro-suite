import pandas as pd
import xml.etree.ElementTree as ET
import os
from datetime import datetime

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

    target_port = None
    for cand in ['port', 'ports']:
        if cand in cols_lower:
            target_port = cols_lower[cand]
            break
    if target_port and target_port not in [target_host, target_sev, target_nvt]:
        col_map[target_port] = 'Port'

    res = df.rename(columns=col_map)
    return res.loc[:, ~res.columns.duplicated()].copy()

def export_assets_from_csv(csv_path: str, output_path: str = None) -> pd.DataFrame:
    """Parses OpenVAS CSV report and extracts a standard CMDB asset inventory format."""
    df = pd.read_csv(csv_path)
    df = normalize_columns(df)

    if 'Hostname' not in df.columns:
        raise ValueError("CSV report must contain a Hostname/IP column.")

    def get_ports(series):
        ports = set(series.dropna().astype(str))
        clean_ports = sorted([p for p in ports if p and p.lower() != 'nan'])
        return ', '.join(clean_ports) if clean_ports else 'None'

    grouped = df.groupby('Hostname').agg(
        Open_Ports=('Port', get_ports) if 'Port' in df.columns else ('Hostname', lambda x: 'Unknown'),
        Total_Vulnerabilities=('NVT Name', 'count') if 'NVT Name' in df.columns else ('Hostname', lambda x: 0),
        Highest_Severity=('Severity', lambda s: s.iloc[0] if len(s) > 0 else 'Unknown')
    ).reset_index()

    grouped.rename(columns={'Hostname': 'Hostname_IP'}, inplace=True)
    grouped['Asset_ID'] = [f"AST-{1000 + i}" for i in range(len(grouped))]
    grouped['MAC_Address'] = "N/A (Derived from IP)"
    grouped['Operating_System'] = "Discovered via OpenVAS Scan"
    grouped['CMDB_Status'] = "Active Discovered Asset"
    grouped['Last_Discovered'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cmdb_cols = [
        'Asset_ID', 'Hostname_IP', 'MAC_Address', 'Operating_System',
        'Open_Ports', 'Total_Vulnerabilities', 'Highest_Severity',
        'CMDB_Status', 'Last_Discovered'
    ]
    cmdb_df = grouped[cmdb_cols]

    if output_path:
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        cmdb_df.to_csv(output_path, index=False)
        print(f"[CMDB Exporter] Asset inventory saved to {output_path}")

    return cmdb_df
