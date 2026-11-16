#!/usr/bin/env python3
"""
LAN Device Discovery & Rogue Device Monitor
-------------------------------------------
Scans the local network periodically, keeps an approved-device list
(MAC / vendor / label) in SQLite and raises an alert when an unknown
device joins. Also flags ARP-poisoning symptoms (two MACs claiming one IP).

Use ONLY on networks you own or are authorised to monitor.

Usage:
  sudo python3 lan_monitor.py baseline            # learn current devices as APPROVED
  sudo python3 lan_monitor.py scan                # one scan + alerts
  sudo python3 lan_monitor.py monitor -i 60       # scan every 60 s
  python3 lan_monitor.py list                     # show all devices
  python3 lan_monitor.py approve AA:BB:CC:DD:EE:FF --label "Dad's phone"
  python3 lan_monitor.py revoke  AA:BB:CC:DD:EE:FF
  python3 lan_monitor.py events -n 30             # alert history

Scanning modes:
  * ARP sweep via scapy (needs root/admin + `pip install scapy`)  -> most accurate
  * Fallback: ping sweep + system ARP table (no root, no extra libs)
"""
import argparse, concurrent.futures as cf, ipaddress, json, os, platform
import re, smtplib, socket, sqlite3, subprocess, sys, time, urllib.request
from datetime import datetime
from email.message import EmailMessage

DB_FILE = os.environ.get("LANMON_DB", "lan_monitor.db")
LOG_FILE = os.environ.get("LANMON_LOG", "alerts.log")
MISS_LIMIT = 2          # scans a device may be missing before marked offline
MAC_RE = re.compile(r"([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Small built-in OUI table (extend with --oui-file, a "AABBCC<TAB>Vendor" list,
# e.g. exported from https://standards-oui.ieee.org/oui/oui.txt)
OUI = {
    "FC:FB:FB": "Cisco", "00:1A:2B": "Ayecom", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "00:50:56": "VMware",
    "08:00:27": "VirtualBox", "00:0C:29": "VMware", "3C:5A:B4": "Google",
    "F4:F5:D8": "Google", "AC:BC:32": "Apple", "F0:18:98": "Apple",
    "A4:83:E7": "Apple", "00:17:F2": "Apple", "BC:92:6B": "Apple",
    "FC:A6:67": "Amazon", "44:65:0D": "Amazon", "00:16:EA": "Intel",
    "3C:97:0E": "Intel", "A4:4C:C8": "Intel", "9C:B6:D0": "Rivet/Intel",
    "00:1B:63": "Apple", "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi",
    "50:8F:4C": "Xiaomi", "FC:64:BA": "Xiaomi", "A0:F3:C1": "TP-Link",
    "50:C7:BF": "TP-Link", "F4:F2:6D": "TP-Link", "C4:E9:84": "TP-Link",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM", "D8:BB:C1": "Micro-Star",
    "BC:D1:D3": "Samsung", "8C:F5:A3": "Samsung", "CC:07:AB": "Samsung",
    "84:D6:D0": "Amazon", "70:3A:CB": "Google", "E8:D8:D1": "Huawei",
    "00:9A:CD": "Huawei", "88:28:B3": "Huawei", "3C:84:6A": "TP-Link",
}


# ----------------------------------------------------------------- helpers
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def norm_mac(mac):
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).upper()


def load_oui_file(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" not in line:
                continue
            m = re.match(r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)", line)
            if m:
                OUI[":".join(m.group(i).upper() for i in (1, 2, 3))] = m.group(4).strip()


def vendor_of(mac):
    v = OUI.get(mac[:8])
    if v:
        return v
    if int(mac[:2], 16) & 0x02:          # locally-administered bit
        return "Randomized/Private MAC"
    return "Unknown"


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "192.168.1.2"
    finally:
        s.close()


def default_subnet():
    return str(ipaddress.ip_network(local_ip() + "/24", strict=False))


def resolve_name(ip):
    try:
        socket.setdefaulttimeout(1)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ----------------------------------------------------------------- scanning
def scan_arp_scapy(subnet, timeout=2):
    """Returns list of (ip, mac). Raises on missing scapy / privileges."""
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(pkt, timeout=timeout, retry=1)
    return [(rcv.psrc, norm_mac(rcv.hwsrc)) for _, rcv in answered]


def _ping(ip):
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait = ["-w", "700"] if platform.system() == "Windows" else ["-W", "1"]
    subprocess.run(["ping", flag, "1", *wait, ip], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def scan_ping_fallback(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()]
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(_ping, hosts))
    out = ""
    for cmd in (["ip", "neigh"], ["arp", "-a"], ["arp", "-an"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
            if out.strip():
                break
        except Exception:
            continue
    found = {}
    for line in out.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        ip, mac = ip_m.group(1), norm_mac(mac_m.group(1))
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or "incomplete" in line.lower():
            continue
        try:
            if ipaddress.ip_address(ip) in net and not ipaddress.ip_address(ip).is_multicast:
                found[(ip, mac)] = 1
        except ValueError:
            pass
    return list(found)


def scan_network(subnet):
    try:
        res, mode = scan_arp_scapy(subnet), "ARP (scapy)"
    except Exception as e:
        print(f"[i] ARP scan unavailable ({type(e).__name__}); using ping+ARP-table fallback.")
        res, mode = scan_ping_fallback(subnet), "ping + ARP table"
    return res, mode


# ----------------------------------------------------------------- database
def db_connect():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS devices(
        mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, hostname TEXT,
        status TEXT DEFAULT 'unknown',      -- approved | unknown
        label TEXT DEFAULT '', first_seen TEXT, last_seen TEXT,
        online INTEGER DEFAULT 0, missed INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, level TEXT,
        type TEXT, mac TEXT, ip TEXT, details TEXT);
    """)
    return con


# ----------------------------------------------------------------- alerting
COLORS = {"CRITICAL": "\033[91m", "WARNING": "\033[93m", "INFO": "\033[96m"}


def alert(con, level, typ, mac, ip, details, notify=None):
    ts = now()
    con.execute("INSERT INTO events(ts,level,type,mac,ip,details) VALUES(?,?,?,?,?,?)",
                (ts, level, typ, mac, ip, details))
    line = f"[{ts}] {level:8} {typ}: {details} (MAC {mac}, IP {ip})"
    print(f"{COLORS.get(level, '')}{line}\033[0m")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if notify and level in ("CRITICAL", "WARNING"):
        send_external(notify, line)


def send_external(cfg, text):
    """Optional webhook (Slack/Discord/Telegram-style) and e-mail."""
    if cfg.get("webhook"):
        try:
            body = json.dumps({"text": text, "content": text}).encode()
            req = urllib.request.Request(cfg["webhook"], body, {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=8)
        except Exception as e:
            print(f"[!] webhook failed: {e}")
    host = os.environ.get("SMTP_HOST")
    if host and os.environ.get("ALERT_TO"):
        try:
            msg = EmailMessage()
            msg["Subject"] = "LAN Monitor alert"
            msg["From"] = os.environ.get("SMTP_USER", "lanmonitor@localhost")
            msg["To"] = os.environ["ALERT_TO"]
            msg.set_content(text)
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=10) as s:
                s.starttls()
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
                s.send_message(msg)
        except Exception as e:
            print(f"[!] email failed: {e}")


# ----------------------------------------------------------------- core logic
def process_scan(con, results, notify=None, baseline=False):
    ts = now()
    seen_macs = set()

    # ARP-poisoning symptom: several MACs answering for the same IP in one scan
    by_ip = {}
    for ip, mac in results:
        by_ip.setdefault(ip, set()).add(mac)
    for ip, macs in by_ip.items():
        if len(macs) > 1 and not baseline:
            alert(con, "CRITICAL", "ARP_SPOOF_SUSPECTED", ",".join(sorted(macs)), ip,
                  f"Multiple MACs claim {ip}", notify)

    for ip, mac in sorted(set(results), key=lambda r: tuple(map(int, r[0].split(".")))):
        seen_macs.add(mac)
        row = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        vendor = vendor_of(mac)
        host = resolve_name(ip)

        if row is None:
            status = "approved" if baseline else "unknown"
            con.execute("""INSERT INTO devices(mac,ip,vendor,hostname,status,first_seen,last_seen,online)
                           VALUES(?,?,?,?,?,?,?,1)""", (mac, ip, vendor, host, status, ts, ts))
            if not baseline:
                alert(con, "CRITICAL", "ROGUE_DEVICE",
                      mac, ip, f"UNKNOWN device joined: vendor={vendor}, host={host or '-'}", notify)
            continue

        # known device
        if row["status"] != "approved" and not row["online"]:
            alert(con, "CRITICAL", "ROGUE_DEVICE", mac, ip,
                  f"Unapproved device is back on the network: vendor={row['vendor']}", notify)
        if row["ip"] != ip and row["status"] == "approved":
            alert(con, "WARNING", "IP_CHANGED", mac, ip,
                  f"Approved device changed IP {row['ip']} -> {ip}", notify)
        con.execute("""UPDATE devices SET ip=?, hostname=COALESCE(NULLIF(?,''),hostname), last_seen=?,
                       online=1, missed=0 WHERE mac=?""", (ip, host, ts, mac))

    # mark devices that vanished
    for row in con.execute("SELECT * FROM devices WHERE online=1").fetchall():
        if row["mac"] in seen_macs:
            continue
        missed = row["missed"] + 1
        if missed >= MISS_LIMIT:
            con.execute("UPDATE devices SET online=0, missed=? WHERE mac=?", (missed, row["mac"]))
            alert(con, "INFO", "DEVICE_LEFT", row["mac"], row["ip"],
                  f"{row['label'] or row['vendor']} left the network")
        else:
            con.execute("UPDATE devices SET missed=? WHERE mac=?", (missed, row["mac"]))
    con.commit()


def do_scan(con, args, baseline=False):
    subnet = args.subnet or default_subnet()
    print(f"[*] Scanning {subnet} ...")
    results, mode = scan_network(subnet)
    print(f"[*] Mode: {mode} | responding hosts: {len(set(results))}")
    process_scan(con, results, {"webhook": args.webhook}, baseline)
    return len(set(results))


# ----------------------------------------------------------------- commands
def cmd_list(con, _):
    rows = con.execute("SELECT * FROM devices ORDER BY status, ip").fetchall()
    print(f"{'STATUS':9} {'ON':3} {'IP':15} {'MAC':17} {'VENDOR':24} {'LABEL/HOST'}")
    print("-" * 90)
    for r in rows:
        flag = "!!" if r["status"] != "approved" else "  "
        print(f"{r['status']:9} {'yes' if r['online'] else 'no ':3} {r['ip'] or '':15} {r['mac']:17} "
              f"{(r['vendor'] or '')[:23]:24} {r['label'] or r['hostname'] or ''} {flag}")
    print(f"\n{len(rows)} devices | {sum(1 for r in rows if r['status'] != 'approved')} unapproved")


def cmd_approve(con, args):
    mac = norm_mac(args.mac)
    cur = con.execute("UPDATE devices SET status='approved', label=? WHERE mac=?", (args.label, mac))
    if cur.rowcount == 0:      # allow pre-approving a device not yet seen
        con.execute("INSERT INTO devices(mac,vendor,status,label,first_seen) VALUES(?,?,?,?,?)",
                    (mac, vendor_of(mac), "approved", args.label, now()))
    con.commit()
    print(f"[+] {mac} approved")


def cmd_revoke(con, args):
    mac = norm_mac(args.mac)
    con.execute("UPDATE devices SET status='unknown' WHERE mac=?", (mac,))
    con.commit()
    print(f"[-] {mac} approval revoked")


def cmd_events(con, args):
    for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (args.n,)).fetchall()[::-1]:
        print(f"[{r['ts']}] {r['level']:8} {r['type']}: {r['details']} ({r['mac']}, {r['ip']})")


def main():
    p = argparse.ArgumentParser(description="LAN Device Discovery & Rogue Device Monitor")
    p.add_argument("--subnet", help="CIDR to scan (default: your /24)")
    p.add_argument("--webhook", help="URL to POST alerts to (Slack/Discord/etc.)")
    p.add_argument("--oui-file", help="Vendor database file (IEEE oui.txt format)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline", help="scan and approve every device currently present")
    sub.add_parser("scan", help="single scan")
    m = sub.add_parser("monitor", help="scan repeatedly")
    m.add_argument("-i", "--interval", type=int, default=60)
    sub.add_parser("list", help="show device table")
    a = sub.add_parser("approve"); a.add_argument("mac"); a.add_argument("--label", default="")
    r = sub.add_parser("revoke"); r.add_argument("mac")
    e = sub.add_parser("events"); e.add_argument("-n", type=int, default=20)
    args = p.parse_args()

    if args.oui_file:
        load_oui_file(args.oui_file)
    con = db_connect()

    if args.cmd == "baseline":
        n = do_scan(con, args, baseline=True)
        print(f"[+] Baseline saved: {n} devices approved. Review with `list`.")
    elif args.cmd == "scan":
        do_scan(con, args)
    elif args.cmd == "monitor":
        print(f"[*] Monitoring every {args.interval}s. Ctrl+C to stop.")
        try:
            while True:
                do_scan(con, args)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
    elif args.cmd == "list":
        cmd_list(con, args)
    elif args.cmd == "approve":
        cmd_approve(con, args)
    elif args.cmd == "revoke":
        cmd_revoke(con, args)
    elif args.cmd == "events":
        cmd_events(con, args)


if __name__ == "__main__":
    main()
