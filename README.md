# LAN Device Discovery and Rogue Device Monitor

A lightweight, Python-based command-line network security tool that discovers active hosts on a local area network (LAN) via ARP scanning, identifies hardware vendors using IEEE OUI lookups, and logs real-time alerts for unauthorized or unknown rogue devices.

---

## Features

* **ARP Network Discovery:** Scans local IP subnets (e.g., `192.168.50.0/24`) using Scapy to detect live hosts and retrieve their IP and MAC addresses.
* **Offline Vendor Lookup:** Parses an IEEE OUI database (`oui.txt`) to map MAC address prefixes to their respective hardware manufacturers.
* **Rogue Device Detection & Alerting:** Automatically flags unknown devices joining the network and writes timestamped security events to `alerts.log`.
* **Persistent Tracking:** Maintains a historical record of discovered devices and network events in a local SQLite database (`lan_monitor.db`).

---

## Prerequisites

Before running the tool, ensure you have the following installed:

1. **Python 3.8+**
2. **Npcap (Windows users only):** Scapy requires a packet capture driver to send and receive raw ARP packets on Windows.
   * Download and install [Npcap](https://npcap.com/#download).
   * During installation, make sure to check **"Install Npcap in WinPcap API-compatible Mode"**.
3. **Administrator / Root Privileges:** Sending raw network packets requires elevated permissions.

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/LAN-Device-Discovery-and-Rogue-Device-Monitor.git
   cd LAN-Device-Discovery-and-Rogue-Device-Monitor
   ```

2. **Install required Python dependencies:**
   ```bash
   pip install scapy
   ```

3. **Verify the OUI database file:**
   Ensure `oui.txt` is present in the root directory alongside `lan_monitor.py` so the script can resolve MAC addresses to vendor names.

---

## Usage

Open your terminal or Command Prompt **as Administrator** (Windows) or with `sudo` (Linux/macOS), navigate to the project directory, and run the following commands:

### 1. Run a Network Scan
Scan the local subnet for active devices and check for new or unauthorized endpoints:
```bash
python lan_monitor.py scan
```

### 2. View Recent Security Events
Display the most recent network and rogue device events recorded in the database (e.g., the last 10 events):
```bash
python lan_monitor.py events -n 10
```

### 3. Check Critical Rogue Device Alerts
View raw critical alerts logged when an unrecognized MAC address joins the network:
* **Windows:**
  ```cmd
  type alerts.log
  ```
* **Linux / macOS:**
  ```bash
  cat alerts.log
  ```

---

## Project Structure

```text
├── lan_monitor.py    # Main CLI script for ARP scanning, OUI resolution, and alerting
├── oui.txt           # IEEE OUI vendor lookup table
├── .gitignore        # Excludes local logs, SQLite database, and Python cache files
├── lan_monitor.db    # Local SQLite database (auto-generated on first run)
└── alerts.log        # Security alert log file (auto-generated when rogue devices appear)
```

---

## Disclaimer

This tool is intended for network administration, educational purposes, and authorized security auditing on networks you own or have explicit permission to monitor.