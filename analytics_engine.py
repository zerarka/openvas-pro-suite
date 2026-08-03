import pandas as pd
import numpy as np
import fp_manager
import threat_intel

SEVERITY_WEIGHTS = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 1,
    'Log': 0
}

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalizes column names cleanly without introducing duplicate column names."""
    if df.empty:
        return df

    # Deduplicate original columns first
    df = df.loc[:, ~df.columns.duplicated()].copy()

    col_map = {}
    cols_lower = {str(col).strip().lower(): col for col in df.columns}

    # Pick single best column for Hostname: 'ip', 'hostname', 'host', 'target'
    target_host = None
    for cand in ['ip', 'hostname', 'host', 'target']:
        if cand in cols_lower:
            target_host = cols_lower[cand]
            break
    if target_host:
        col_map[target_host] = 'Hostname'

    # Pick single best column for Severity: 'severity', 'threat', 'cvss_severity', 'cvss'
    target_sev = None
    for cand in ['severity', 'threat', 'cvss_severity', 'cvss']:
        if cand in cols_lower:
            target_sev = cols_lower[cand]
            break
    if target_sev and target_sev != target_host:
        col_map[target_sev] = 'Severity'

    # Pick single best column for NVT Name: 'nvt name', 'nvt', 'vulnerability', 'vulnerability name', 'name'
    target_nvt = None
    for cand in ['nvt name', 'nvt', 'vulnerability', 'vulnerability name', 'name']:
        if cand in cols_lower:
            target_nvt = cols_lower[cand]
            break
    if target_nvt and target_nvt not in [target_host, target_sev]:
        col_map[target_nvt] = 'NVT Name'

    # Pick single best column for Port: 'port', 'ports'
    target_port = None
    for cand in ['port', 'ports']:
        if cand in cols_lower:
            target_port = cols_lower[cand]
            break
    if target_port and target_port not in [target_host, target_sev, target_nvt]:
        col_map[target_port] = 'Port'

    # Pick single best column for CVEs: 'cve', 'cves', 'cve id'
    target_cves = None
    for cand in ['cve', 'cves', 'cve id', 'cves id', 'cve_id']:
        if cand in cols_lower:
            target_cves = cols_lower[cand]
            break
    if target_cves and target_cves not in [target_host, target_sev, target_nvt, target_port]:
        col_map[target_cves] = 'CVEs'

    res = df.rename(columns=col_map)
    return res.loc[:, ~res.columns.duplicated()].copy()

def get_risk_score(csv_path: str, exclude_fp: bool = True) -> pd.DataFrame:
    """Reads an OpenVAS CSV report, adds Threat Intel, and calculates risk scores."""
    df = pd.read_csv(csv_path)
    df = normalize_columns(df)

    if 'Hostname' not in df.columns or 'Severity' not in df.columns:
        raise ValueError("CSV missing required 'Hostname' or 'Severity' columns.")

    if exclude_fp:
        df = fp_manager.filter_false_positives(df)

    df = threat_intel.enrich_vulnerabilities(df, cve_col='CVEs' if 'CVEs' in df.columns else 'CVE')

    if df.empty:
        return pd.DataFrame(columns=['Hostname', 'Severity', 'NVT Name', 'CISA KEV', 'EPSS Score', 'Risk Score'])

    df['Base Weight'] = df['Severity'].astype(str).str.capitalize().map(SEVERITY_WEIGHTS).fillna(0)
    
    # Calculate Individual Risk Score for the vulnerability
    # CISA KEV gives a massive bump, EPSS gives a moderate bump
    df['Risk Score'] = df['Base Weight']
    if 'CISA KEV' in df.columns:
        df.loc[df['CISA KEV'] == True, 'Risk Score'] += 50
    if 'EPSS Score' in df.columns:
        df['Risk Score'] += df['EPSS Score'].fillna(0.0) * 10.0
        
    # Return the detailed DataFrame so UI can show all columns, including Severity, NVT Name, KEV, EPSS
    return df.sort_values(by='Risk Score', ascending=False)

def get_multiple_risk_scores(csv_paths: list, exclude_fp: bool = True) -> pd.DataFrame:
    """Reads multiple OpenVAS CSV reports, combines them, enriches with Threat Intel, and calculates risk scores."""
    dfs = []
    for p in csv_paths:
        try:
            df = pd.read_csv(p)
            df = normalize_columns(df)
            if 'Hostname' in df.columns and 'Severity' in df.columns:
                if exclude_fp:
                    df = fp_manager.filter_false_positives(df)
                df['Report_Source'] = os.path.basename(p)
                dfs.append(df)
        except Exception as e:
            print(f"[Analytics Engine Error] Error reading {p}: {e}")

    if not dfs:
        return pd.DataFrame(columns=['Hostname', 'Severity', 'NVT Name', 'Report_Source', 'CISA KEV', 'EPSS Score', 'Risk Score'])

    combined = pd.concat(dfs, ignore_index=True)
    combined = threat_intel.enrich_vulnerabilities(combined, cve_col='CVEs' if 'CVEs' in combined.columns else 'CVE')

    combined['Base Weight'] = combined['Severity'].astype(str).str.capitalize().map(SEVERITY_WEIGHTS).fillna(0)
    combined['Risk Score'] = combined['Base Weight']
    if 'CISA KEV' in combined.columns:
        combined.loc[combined['CISA KEV'] == True, 'Risk Score'] += 50
    if 'EPSS Score' in combined.columns:
        combined['Risk Score'] += combined['EPSS Score'].fillna(0.0) * 10.0

    return combined.sort_values(by='Risk Score', ascending=False)

def get_host_risk_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Summarizes detailed risk DataFrame into Host-level aggregated scores."""
    if df.empty or 'Hostname' not in df.columns or 'Risk Score' not in df.columns:
        return pd.DataFrame(columns=['Hostname', 'Risk Score'])
    
    score_df = df.groupby('Hostname')['Risk Score'].sum().reset_index()
    return score_df.sort_values(by='Risk Score', ascending=False)

def calculate_delta(old_csv: str, new_csv: str, exclude_fp: bool = True) -> pd.DataFrame:
    """Compares two CSV reports to find new and resolved vulnerabilities."""
    df_old = pd.read_csv(old_csv)
    df_new = pd.read_csv(new_csv)

    df_old = normalize_columns(df_old)
    df_new = normalize_columns(df_new)

    if exclude_fp:
        df_old = fp_manager.filter_false_positives(df_old)
        df_new = fp_manager.filter_false_positives(df_new)
        
    df_old = threat_intel.enrich_vulnerabilities(df_old, cve_col='CVEs' if 'CVEs' in df_old.columns else 'CVE')
    df_new = threat_intel.enrich_vulnerabilities(df_new, cve_col='CVEs' if 'CVEs' in df_new.columns else 'CVE')

    df_old['Hostname'] = df_old['Hostname'].fillna('Unknown')
    df_old['NVT Name'] = df_old.get('NVT Name', pd.Series('Unknown Vulnerability', index=df_old.index)).fillna('Unknown Vulnerability')
    
    df_new['Hostname'] = df_new['Hostname'].fillna('Unknown')
    df_new['NVT Name'] = df_new.get('NVT Name', pd.Series('Unknown Vulnerability', index=df_new.index)).fillna('Unknown Vulnerability')

    df_old['key'] = df_old['Hostname'].astype(str) + "_" + df_old['NVT Name'].astype(str)
    df_new['key'] = df_new['Hostname'].astype(str) + "_" + df_new['NVT Name'].astype(str)
    
    new_vulns = df_new[~df_new['key'].isin(df_old['key'])].copy()
    new_vulns['Status'] = 'NEW'
    
    resolved_vulns = df_old[~df_old['key'].isin(df_new['key'])].copy()
    resolved_vulns['Status'] = 'RESOLVED'
    
    delta_df = pd.concat([new_vulns, resolved_vulns], ignore_index=True)
    
    if delta_df.empty:
        return pd.DataFrame(columns=['Hostname', 'NVT Name', 'Severity', 'CISA KEV', 'EPSS Score', 'Status'])

    cols = ['Hostname', 'NVT Name', 'Severity', 'CISA KEV', 'EPSS Score', 'Status']
    available_cols = [c for c in cols if c in delta_df.columns]
    return delta_df[available_cols]

def get_asset_inventory(csv_path: str) -> pd.DataFrame:
    """Extracts unique host information from a scan report."""
    df = pd.read_csv(csv_path)
    df = normalize_columns(df)
    
    if 'Hostname' not in df.columns:
        return pd.DataFrame(columns=['Hostname', 'Port'])

    if 'Port' not in df.columns:
        df['Port'] = 'Unknown'

    assets = df.groupby('Hostname').agg({
        'Port': lambda x: ', '.join(map(str, sorted(set(x.dropna()))))
    }).reset_index()
    
    return assets