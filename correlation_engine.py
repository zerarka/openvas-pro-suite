import ipaddress
import pandas as pd
from typing import List

SEVERITY_WEIGHTS = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 1,
    'Log': 0
}

def extract_subnet(ip_or_host, mask: str = "/24") -> str:
    """Infers network subnet from an IP address or hostname safely."""
    if isinstance(ip_or_host, (pd.Series, pd.DataFrame)):
        ip_or_host = str(ip_or_host.iloc[0]) if len(ip_or_host) > 0 else ""
    elif not isinstance(ip_or_host, str):
        ip_or_host = str(ip_or_host)

    clean_val = ip_or_host.strip()
    if not clean_val or clean_val.lower() == 'nan':
        return "Unknown Subnet"

    try:
        ip = ipaddress.ip_address(clean_val)
        network = ipaddress.ip_network(f"{ip}{mask}", strict=False)
        return str(network)
    except ValueError:
        parts = clean_val.split(".")
        if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "Internal VLAN Domain"

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

def find_master_targets(csv_paths: List[str], fp_filter_fn=None, mask="/24", progress_callback=None) -> pd.DataFrame:
    """Correlates vulnerabilities across all loaded scan reports / VLANs to identify 'Master Targets'."""
    frames = []
    total_files = len(csv_paths)
    for idx, path in enumerate(csv_paths):
        if progress_callback and callable(progress_callback):
            progress_callback(idx + 1, total_files, f"Analyzing report {idx+1}/{total_files}...")
        try:
            df = pd.read_csv(path)
            df = normalize_columns(df)
            if fp_filter_fn and callable(fp_filter_fn):
                df = fp_filter_fn(df)
            if 'Hostname' in df.columns and 'NVT Name' in df.columns:
                frames.append(df)
        except Exception as e:
            print(f"[Correlation Engine Error] Reading {path}: {e}")

    if not frames:
        return pd.DataFrame(columns=[
            'NVT Name', 'Severity', 'Subnets Spanned', 'Total Hosts Affected', 'Master Target Score', 'Affected Subnets', 'Sample Affected Hosts'
        ])

    full_df = pd.concat(frames, ignore_index=True).drop_duplicates(subset=['Hostname', 'NVT Name'])
    
    full_df['Subnet'] = full_df['Hostname'].apply(lambda h: extract_subnet(h, mask=mask))
    full_df['Weight'] = full_df['Severity'].astype(str).str.capitalize().map(SEVERITY_WEIGHTS).fillna(0)

    grouped = full_df.groupby('NVT Name').agg(
        Severity=('Severity', 'first'),
        Weight=('Weight', 'max'),
        Subnet_Set=('Subnet', lambda s: sorted(set(s))),
        Subnet_Count=('Subnet', lambda s: len(set(s))),
        Host_Count=('Hostname', 'nunique'),
        Affected_Hosts=('Hostname', lambda h: ', '.join(sorted(set(h.astype(str)))[:10]))
    ).reset_index()

    grouped['Master Target Score'] = grouped['Subnet_Count'] * 5 + grouped['Weight']
    grouped['Affected Subnets'] = grouped['Subnet_Set'].apply(lambda s: ', '.join(s))

    cols_order = [
        'NVT Name', 'Severity', 'Subnet_Count', 'Host_Count',
        'Master Target Score', 'Affected Subnets', 'Affected_Hosts'
    ]
    
    result = grouped[cols_order].sort_values(by='Master Target Score', ascending=False)
    result.rename(columns={
        'Subnet_Count': 'Subnets Spanned',
        'Host_Count': 'Total Hosts Affected',
        'Affected_Hosts': 'Sample Affected Hosts'
    }, inplace=True)
    
    return result
