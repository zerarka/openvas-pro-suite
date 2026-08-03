# 🛡️ OpenVAS Pro Suite — Modern Risk-Based Vulnerability Management (v4.0)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Theme: ttkbootstrap](https://img.shields.io/badge/UI-ttkbootstrap-purple.svg)](https://ttkbootstrap.readthedocs.io/)

**OpenVAS Pro Suite** is a high-performance desktop application designed to transform raw Greenbone / OpenVAS vulnerability scans into actionable **Risk-Based Vulnerability Management (RBVM)** intelligence.

Featuring a modern dark-mode SaaS sidebar interface, real-world **CISA KEV** & **EPSS** threat intelligence integration, cross-VLAN master target correlation, trend heatmaps, CMDB asset inventory, network topology rendering, and remediation SLA tracking.

---

## 🌟 Key Features

### 1. 🛡️ Real-Time Threat Intelligence (CISA KEV & EPSS)
- Dynamically fetches active threat intelligence feeds from **CISA KEV** (Known Exploited Vulnerabilities) and **EPSS** (Exploit Prediction Scoring System).
- Automatically recalculates risk scores, heavily prioritizing vulnerabilities actively exploited in the wild (+50 point risk score amplification).

### 2. 🔌 Automated SSH Tunneling & Live GVM Integration
- Native Paramiko SSH tunneling with binary `direct-tcpip` port forwarding.
- Query all 9 Greenbone menu entities directly: **Reports, Tasks, Results, Vulnerabilities, Notes, Overrides, Hosts, Operating Systems, and TLS Certificates**.
- Delete unwanted remote reports directly from OpenVAS via GMP API.

### 3. 🌐 Cross-VLAN Master Target Correlation
- Analyzes vulnerability distributions across your entire infrastructure to isolate **Master Targets**—servers harboring vulnerabilities that span the widest number of subnets.

### 4. 📈 Trend Analysis & Heatmaps
- Aggregates historical scan series to plot risk trends (Rising 🔴, Falling 🟢, Stable 🟡) over time using embedded Matplotlib figures.

### 5. ⏱️ Remediation SLA Manager
- Compares sequential scan reports to track carried-over unresolved vulnerabilities and automatically flags Critical/High severity items breaching remediation SLAs.

### 6. 🗺️ Live CMDB Inventory & Network Topology Map
- Converts scan results into structured CMDB Asset Inventories (`Asset_ID`, `Hostname_IP`, `MAC_Address`, `Operating_System`, `Open_Ports`).
- Renders interactive network topology maps using NetworkX.

---

## 💻 Modern UI Architecture
Built with `ttkbootstrap` using the high-contrast `superhero` dark theme and clean SaaS sidebar navigation layout:
- **Scan Management:** Reports & GVM Live
- **Threat & Risk Analytics:** Threat Intel Analytics, False Positives Audit, Trend Heatmaps, Master Targets
- **Infrastructure & Assets:** Network Topology & CMDB Inventory, Remediation SLAs

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure Python 3.10+ is installed. Install required dependencies:
```bash
pip install ttkbootstrap python-gvm paramiko pandas numpy matplotlib seaborn networkx openpyxl requests
```

### 2. Configuration
Copy `config.example.json` to `config.json` and configure your default SSH / GVM settings:
```json
{
  "ssh": {
    "host": "192.168.1.100",
    "username": "admin",
    "port": 22
  },
  "gvm": {
    "username": "admin",
    "socket_path": "/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock",
    "local_tunnel_port": 9390
  },
  "paths": {
    "report_download_dir": "./reports"
  }
}
```

### 3. Launch Application
```bash
python desktop_app.py
```

---

## 📄 License
Distributed under the **MIT License**. See `LICENSE` for more information.
