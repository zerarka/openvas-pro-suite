import pandas as pd
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_KEV_CACHE = None
_EPSS_CACHE = None

def _fetch_kev():
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    try:
        resp = requests.get(KEV_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if 'vulnerabilities' in data:
                _KEV_CACHE = pd.DataFrame(data['vulnerabilities'])
                return _KEV_CACHE
    except Exception as e:
        print(f"Failed to fetch KEV: {e}")
    return pd.DataFrame()

def _fetch_epss():
    global _EPSS_CACHE
    if _EPSS_CACHE is not None:
        return _EPSS_CACHE
    try:
        # The first line of EPSS CSV is a comment starting with #
        _EPSS_CACHE = pd.read_csv(EPSS_URL, compression='gzip', comment='#')
        return _EPSS_CACHE
    except Exception as e:
        print(f"Failed to fetch EPSS: {e}")
    return pd.DataFrame()

def enrich_vulnerabilities(df: pd.DataFrame, cve_col: str = 'CVEs') -> pd.DataFrame:
    """
    Adds 'CISA KEV' (bool) and 'EPSS Score' (float) to the DataFrame based on CVEs.
    cve_col can contain comma-separated CVEs (e.g. 'CVE-2021-1234, CVE-2022-5678').
    """
    if df.empty or cve_col not in df.columns:
        df['CISA KEV'] = False
        df['EPSS Score'] = 0.0
        return df

    kev_df = _fetch_kev()
    epss_df = _fetch_epss()

    cisa_set = set(kev_df['cveID'].dropna().values) if not kev_df.empty and 'cveID' in kev_df.columns else set()
    
    epss_dict = {}
    if not epss_df.empty and 'cve' in epss_df.columns and 'epss' in epss_df.columns:
        epss_dict = dict(zip(epss_df['cve'], epss_df['epss']))

    def is_kev(cves_str):
        if pd.isna(cves_str) or str(cves_str).strip() == '' or str(cves_str).upper() == 'NOCVE':
            return False
        cves = [c.strip() for c in str(cves_str).split(',')]
        for c in cves:
            if c in cisa_set:
                return True
        return False

    def get_max_epss(cves_str):
        if pd.isna(cves_str) or str(cves_str).strip() == '' or str(cves_str).upper() == 'NOCVE':
            return 0.0
        cves = [c.strip() for c in str(cves_str).split(',')]
        max_score = 0.0
        for c in cves:
            s = float(epss_dict.get(c, 0.0))
            if s > max_score:
                max_score = s
        return max_score

    df['CISA KEV'] = df[cve_col].apply(is_kev)
    df['EPSS Score'] = df[cve_col].apply(get_max_epss)
    
    return df
