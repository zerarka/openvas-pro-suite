import ipaddress
import pandas as pd
import numpy as np
import networkx as nx
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

SEVERITY_WEIGHTS = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 1,
    'Log': 0
}

def extract_subnet(ip_or_host, mask: str = "/24") -> str:
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

def build_network_topology_figure(csv_path: str, mask="/24", fp_filter_fn=None) -> plt.Figure:
    """Builds a NetworkX network topology graph from OpenVAS CSV report data."""
    fig, ax = plt.subplots(figsize=(8, 6), dpi=100)
    fig.patch.set_facecolor('#f5f5f7')
    ax.set_facecolor('#ffffff')

    try:
        df = pd.read_csv(csv_path)
        df = normalize_columns(df)
        if fp_filter_fn and callable(fp_filter_fn):
            df = fp_filter_fn(df)
    except Exception as e:
        ax.text(0.5, 0.5, f"Error loading CSV for topology: {e}", ha='center', va='center')
        ax.axis('off')
        return fig

    if 'Hostname' not in df.columns:
        ax.text(0.5, 0.5, "CSV missing Hostname column", ha='center', va='center')
        ax.axis('off')
        return fig

    df['Weight'] = df['Severity'].astype(str).str.capitalize().map(SEVERITY_WEIGHTS).fillna(0)
    
    host_scores = df.groupby('Hostname')['Weight'].sum().to_dict()

    G = nx.Graph()

    subnet_hosts = {}
    for host in host_scores.keys():
        subnet = extract_subnet(host, mask=mask)
        if subnet not in subnet_hosts:
            subnet_hosts[subnet] = []
        subnet_hosts[subnet].append(host)

    G.add_node("OpenVAS Scanner", node_type="scanner", color="#2c3e50", size=1200)

    for subnet, hosts in subnet_hosts.items():
        G.add_node(subnet, node_type="subnet", color="#2980b9", size=900)
        G.add_edge("OpenVAS Scanner", subnet)

        for host in hosts:
            risk = host_scores[host]
            if risk >= 25:
                color = "#e74c3c"
            elif risk >= 10:
                color = "#e67e22"
            elif risk >= 4:
                color = "#f1c40f"
            else:
                color = "#2ecc71"

            size = 400 + min(risk * 20, 800)
            G.add_node(host, node_type="host", color=color, size=size, risk=risk)
            G.add_edge(subnet, host)

    colors = [G.nodes[n].get('color', '#95a5a6') for n in G.nodes()]
    sizes = [G.nodes[n].get('size', 400) for n in G.nodes()]

    pos = nx.spring_layout(G, k=0.4, iterations=50, seed=42)

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#bdc3c7", width=1.5, alpha=0.8)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=sizes, edgecolors="#ffffff", linewidths=1.5)

    labels = {}
    for n in G.nodes():
        if G.nodes[n].get('node_type') == 'host':
            labels[n] = f"{n}\n(Score: {G.nodes[n]['risk']})"
        else:
            labels[n] = n

    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=7, font_weight='bold')

    ax.set_title("Network Topology & Asset Vulnerability Risk Map", fontsize=12, fontweight='bold', pad=12)
    ax.axis('off')
    fig.tight_layout()
    return fig
