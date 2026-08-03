# 🛡️ OpenVAS Pro Suite (v4.0) — Enterprise RBVM & High-Scale GVM Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker: Greenbone Community Edition](https://img.shields.io/badge/Docker-GVM%20Community%20Edition-2496ED.svg?logo=docker&logoColor=white)](https://greenbone.github.io/docs/latest/22.4/container/)
[![Protocol: GMP Direct](https://img.shields.io/badge/Protocol-GMP%20Direct%20Streaming-brightgreen.svg)]()
[![Security: Zero--Trust SSH](https://img.shields.io/badge/Transport-Zero--Trust%20SSH%20Socket-success.svg)]()

> **High-Throughput Vulnerability Orchestration & Threat-Informed Prioritization for Dockerized OpenVAS / GVM Infrastructure**

---

## Executive Summary

**OpenVAS Pro Suite** is an enterprise-grade Risk-Based Vulnerability Management (RBVM) orchestrator engineered specifically to eliminate data export bottlenecks and operational friction in high-scale Greenbone Vulnerability Management (GVM) container deployments.

While Greenbone Community Edition (Docker-based) features a robust scanning core (`openvas-scanner` & `gvmd`), the standard web interface—**Greenbone Security Assistant (GSA)**—acts as a severe operational bottleneck. Large-scale enterprise reports routinely trigger **504 Gateway Timeouts**, DOM memory exhaustion, and HTTP webserver crashes during report export.

OpenVAS Pro Suite bypasses GSA entirely. By establishing a direct, multi-threaded binary socket bridge into the internal Docker container socket (`gvmd.sock`) via the **Greenbone Management Protocol (GMP)**, it enables uncapped data streaming, enriches findings with live **CISA KEV** and **EPSS** threat intelligence feeds, maps network topology, and tracks remediation SLA compliance—all over a Zero-Trust SSH connection without exposing vulnerable web management ports.

---

## 🔬 Technical Deep-Dive: GSA Bottleneck vs. GMP-Direct Streaming

### The "Export Limit" Reality
Standard GVM deployments rely on a 3-layer HTTP stack to process user queries:
`Browser UI ──► GSA Webserver (HTTP) ──► gvmd daemon (Unix Socket) ──► PostgreSQL`

When attempting to render or export multi-gigabyte vulnerability reports containing thousands of host results:
1. **HTTP Gateway Timeouts:** Nginx / GSA reverse proxies drop long-running queries with `504 Gateway Timeout` errors.
2. **Browser Memory Exhaustion:** Client-side JavaScript DOM rendering crashes browsers when attempting to paginate or render >10,000 result rows.
3. **API Row Caps:** GSA implicitly caps XML/CSV exports to prevent webserver process starvation.

```
[ STOCK ARCHITECTURE: HIGH-SCALE BOTTLENECK ]
User Browser ──(HTTP / Web Port 9392)──► GSA Reverse Proxy ──(504 Timeout!)──► gvmd daemon

[ PRO SUITE ARCHITECTURE: GMP-DIRECT STREAMING ]
OpenVAS Pro Suite ──(Paramiko SSH Tunnel)──► socat Bridge ──(Direct Binary Unix Socket)──► gvmd.sock
```

### The GMP-Direct Solution
OpenVAS Pro Suite bypasses the HTTP/GSA layer entirely. It establishes a high-throughput, unpaginated binary stream directly over the **Greenbone Management Protocol (GMP)** using a local TCP socket bridge. 

- **Uncapped Throughput:** Exports datasets of any row count or file size without gateway timeouts or pagination caps.
- **Zero Web Footprint:** Eliminates the need to run or expose the GSA web interface (Port 9392).

---

## 🐳 Docker-Optimized Socket Bridge Architecture

In modern Greenbone Community Edition deployments, `gvmd` runs inside an isolated Docker container, exposing its control socket inside a named Docker volume:
`/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock`

Accessing this socket remotely usually requires complex container mounts or manually executing error-prone terminal tunnels. OpenVAS Pro Suite automates this entire transport topology:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      LOCAL SECURITY CONSOLE (GUI)                      │
│   desktop_app.py — Asynchronous ThreadPool Event Loop                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                (Encrypted Paramiko Direct-TCPIP Channel :9390)
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│                 REMOTE LINUX HOST (Docker Container Host)              │
│                                                                        │
│   1. Automated Background Socat Listener:                              │
│      echo 'password' | sudo -S socat TCP-LISTEN:9390,bind=127.0.0.1... │
│                                  │                                     │
│                                  ▼                                     │
│   2. Docker Volume Socket:                                             │
│      /var/lib/docker/volumes/.../_data/gvmd.sock                       │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Automated SSH Port Forwarding:** Uses Paramiko `direct-tcpip` channel creation to bind local port `9390` securely to the remote host.
2. **Automated `socat` Socket Bridging:** Provisions a background non-blocking `socat` listener attached to the Docker volume path.
3. **PTY Echo Isolation:** Bypasses pseudo-terminal (PTY) allocation to prevent password leakage into binary XML streams, ensuring corrupted-free transport.

---

## ⚡ Feature Matrix: Stock GSA vs. OpenVAS Pro Suite

| Operational Vector | Stock Greenbone Security Assistant (GSA) | OpenVAS Pro Suite (v4.0) |
| :--- | :--- | :--- |
| **Export Scaling** | Capped by HTTP webserver limits; frequent **504 Gateway Timeouts** on massive scans. | **Uncapped GMP Streaming:** Direct socket streaming for unpaginated bulk CSV/Excel exports. |
| **Docker Volume Bridging** | Requires manual container port binds or manual CLI `socat` socket tunnels. | **Automated Socket Bridge:** 1-click automated `socat` provisioning for Docker `gvmd.sock` volumes. |
| **Threat Intelligence** | Static CVSS v2/v3 base scores; zero active exploit weaponization context. | **Live RBVM Feeds:** Real-time ingestion & enrichment with **CISA KEV** (+50 risk weight) & **EPSS** scores. |
| **Network Perimeter Hardening**| Requires exposing web management ports (e.g., HTTP/HTTPS Port 9392). | **Zero-Trust Hardening:** Operates exclusively over encrypted SSH (Port 22). Zero web ports exposed. |
| **Multi-Scan Delta Tracking** | Manual, side-by-side visual inspection of individual reports. | **Automated SLA Engine:** Sequential scan delta analysis, carry-over tracking, and SLA breach alerts. |
| **Infrastructure Analytics** | Flat asset lists with no topological correlation. | **NetworkX Graph & CMDB:** Renders interactive network topology maps and exports clean CMDB inventories. |
| **Executive Reporting** | 200+ page raw technical dumps unsuitable for leadership. | **1-Page Executive Dashboards:** HTML executive summaries with threat badges, SLA metrics, and line numbers (`#`). |

---

## 🔒 Security & Privacy Posture

- **Zero External Telemetry:** All data normalization, threat score calculations, delta comparisons, and topology graphings occur **100% locally**. Vulnerability payloads never leave your security perimeter.
- **Zero-Trust Perimeter:** Eliminates the attack surface of web management applications by relying exclusively on SSH public key or password transport.
- **Air-Gap Compliance:** Capable of running in strict, isolated SOC environments with offline threat intelligence caching.

---

## 🚀 Installation & Quick Start (Docker Environment)

### 1. Prerequisites
- **Local Console:** Windows 10/11, Linux, or macOS with Python 3.10+
- **Remote Host:** Linux running Greenbone Community Containers (Docker Compose)

### 2. Quick Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/zerarka/openvas-pro-suite.git
cd openvas-pro-suite
pip install -r requirements.txt
```

### 3. Configuration (`config.json`)
Copy `config.example.json` to `config.json` and set your Docker host details:
```json
{
  "ssh": {
    "host": "10.1.20.8",
    "username": "ops",
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

### 4. Launch Desktop Application
```bash
python desktop_app.py
```

---

## 📄 License
Distributed under the **MIT License**. See `LICENSE` for full details.
