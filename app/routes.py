# app/routes.py

import os
import ipaddress
import socket
import subprocess
import ollama  
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from pathlib import Path
from typing import List, Optional, Dict, Any
from flask import Blueprint, jsonify, request
import psutil
from ping3 import ping
from manuf import manuf
from .models import (
    save_ports_for_ip,
    save_scan_results,
    get_recent_scans,
    get_session_snapshots,
    format_mac,
    format_ip,
)
from .scanner import scan_network


# ---------- Flask blueprint
api = Blueprint("api", __name__, url_prefix="/api") 

# ---------- Path to Manuf file for MAC vendor lookup 
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MANUF = BASE_DIR / "data" / "manuf"
MANUF_PATH = os.environ.get("MANUF_PATH", str(DEFAULT_MANUF))
parser = manuf.MacParser(manuf_name=MANUF_PATH)

VENDOR_MAP_LIST = {
    # =========================
    # Routers / networking
    # =========================
    "cisco systems": "router",
    "cisco": "router",
    "tp-link": "router",
    "tplink": "router",
    "netgear": "router",
    "ubiquiti networks": "router",
    "ubiquiti": "router",
    "mikrotik": "router",
    "linksys": "router",
    "asus": "router",
    "arris": "router",
    "motorola": "router",
    "zyxel": "router",
    "d-link": "router",
    "dlink": "router",
    "huawei technologies": "router",
    "huawei": "router",
    "zte": "router",
    "calix": "router",
    "technicolor": "router",
    "sagemcom": "router",
    "comtrend": "router",
    "arcadyan": "router",
    "sercomm": "router",
    "hitron": "router",
    "actiontec": "router",
    "arris group": "router",

    # Mesh / extenders
    "airties": "extender",
    "eero": "extender",
    "plume": "extender",
    "google wifi": "extender",
    "tp-link extender": "extender",

    # =========================
    # Printers
    # =========================
    "hewlett packard": "printer",
    "hp printer": "printer",
    "hp": "printer",
    "canon": "printer",
    "epson": "printer",
    "brother": "printer",
    "lexmark": "printer",
    "xerox": "printer",
    "ricoh": "printer",
    "kyocera": "printer",
    "zebra": "printer",
    "oki": "printer",
    "sharp printer": "printer",
    "samsung printer": "printer",

    # =========================
    # Phones / tablets
    # =========================
    "apple iphone": "phone",
    "apple ipad": "phone",
    "apple": "phone",
    "samsung mobile": "phone",
    "samsung": "phone",
    "google pixel": "phone",
    "google": "phone",
    "oneplus": "phone",
    "motorola mobility": "phone",
    "xiaomi": "phone",
    "redmi": "phone",
    "oppo": "phone",
    "vivo": "phone",
    "honor": "phone",
    "realme": "phone",
    "nokia": "phone",
    "hmd global": "phone",

    # =========================
    # Laptops / computers
    # =========================
    "hp inc": "laptop",
    "dell": "laptop",
    "lenovo": "laptop",
    "asus computer": "laptop",
    "acer": "laptop",
    "msi": "laptop",
    "microsoft corporation": "laptop",
    "microsoft": "laptop",
    "intel corporate": "laptop",
    "intel": "laptop",
    "gigabyte": "laptop",
    "asrock": "laptop",
    "framework": "laptop",
    "razer": "laptop",
    "alienware": "laptop",

    # =========================
    # Cameras / security
    # =========================
    "hikvision": "camera",
    "dahua": "camera",
    "wyze": "camera",
    "ring": "camera",
    "arlo": "camera",
    "reolink": "camera",
    "amcrest": "camera",
    "axis communications": "camera",
    "axis": "camera",
    "foscam": "camera",
    "ezviz": "camera",
    "uniview": "camera",
    "annke": "camera",
    "tapo": "camera",
    "eufy": "camera",
    "blink": "camera",

    # =========================
    # TVs / streaming devices
    # =========================
    "samsung electronics": "tv",
    "lg electronics": "tv",
    "sony corporation": "tv",
    "sony": "tv",
    "roku": "tv",
    "vizio": "tv",
    "tcl": "tv",
    "hisense": "tv",
    "philips": "tv",
    "sharp": "tv",
    "insignia": "tv",
    "amazon fire tv": "tv",
    "amazon": "tv",
    "google cast": "tv",
    "chromecast": "tv",

    # =========================
    # Smart home / IoT
    # =========================
    "amazon technologies": "iot",
    "google nest": "iot",
    "nest": "iot",
    "ecobee": "iot",
    "sonos": "iot",
    "philips lighting": "iot",
    "philips hue": "iot",
    "lutron": "iot",
    "tuya": "iot",
    "espressif": "iot",
    "raspberry pi": "iot",
    "particle": "iot",
    "belkin": "iot",
    "wemo": "iot",
    "shelly": "iot",
    "meross": "iot",
    "lifx": "iot",
    "nanoleaf": "iot",
    "aqara": "iot",
    "yeelight": "iot",

    # =========================
    # Game consoles
    # =========================
    "sony interactive entertainment": "console",
    "sony interactive": "console",
    "playstation": "console",
    "microsoft xbox": "console",
    "xbox": "console",
    "nintendo": "console",

    # =========================
    # Virtual machines / labs
    # =========================
    "vmware": "virtual_machine",
    "virtualbox": "virtual_machine",
    "oracle virtualbox": "virtual_machine",
    "parallels": "virtual_machine",
    "qemu": "virtual_machine",
    "xen": "virtual_machine",
    "hyper-v": "virtual_machine",
}
VENDOR_MAP = sorted(
    VENDOR_MAP_LIST.items(),
    key=lambda x: len(x[0]),
    reverse=True
)
VULN_SIGNATURES = [
    # Legacy services
    {
        "service": "telnet",
        "severity": "high",
        "label": "Insecure Telnet Service",
        "type": "insecure_service",
        "advice": "Telnet transmits credentials in clear text. Disable it or restrict access.",
        "cve": None,
    },
    {
        "service": "ftp",
        "severity": "medium",
        "label": "Unencrypted FTP Service",
        "type": "insecure_service",
        "advice": "FTP is unencrypted. Use SFTP or FTPS instead.",
        "cve": None,
    },

    # Remote access
    {
        "service": "rdp",
        "severity": "critical",
        "label": "Remote Desktop Exposed",
        "type": "remote_access",
        "advice": "RDP allows remote control. Restrict access and ensure system is patched.",
        "cve": "CVE-2019-0708",
    },
    {
        "service": "vnc",
        "severity": "medium",
        "label": "VNC Remote Access Detected",
        "type": "remote_access",
        "advice": "VNC allows remote screen access. Restrict it to trusted devices only.",
        "cve": None,
    },
    {
        "service": "ssh",
        "severity": "low",
        "label": "SSH Service Open",
        "type": "remote_access",
        "advice": "SSH is open. Ensure strong authentication and disable default credentials.",
        "cve": None,
    },

    # File sharing
    {
        "service": "smb",
        "severity": "critical",
        "label": "SMB File Sharing Reachable",
        "type": "file_sharing",
        "advice": "SMB is reachable. Disable SMBv1 and ensure system is patched.",
        "cve": "CVE-2017-0144",
    },
    {
        "service": "netbios",
        "severity": "medium",
        "label": "NetBIOS Service Detected",
        "type": "file_sharing",
        "advice": "NetBIOS can expose network information. Disable if not needed.",
        "cve": None,
    },

    # Web services
    {
        "service": "http",
        "severity": "low",
        "label": "HTTP Service Open",
        "type": "web_service",
        "advice": "A web service is reachable. Ensure it is intended and secured.",
        "cve": None,
    },
    {
        "service": "http",
        "contains": "apache",
        "severity": "info",
        "label": "Apache Web Server Detected",
        "type": "fingerprint",
        "advice": "Apache server detected. Ensure it is updated to the latest version.",
        "cve": None,
    },
    {
        "service": "http",
        "contains": "apache 2.4.49",
        "severity": "high",
        "label": "Vulnerable Apache Version",
        "type": "known_vulnerability",
        "advice": "Apache 2.4.49 vulnerable to path traversal. Patch immediately.",
        "cve": "CVE-2021-41773",
    },
    {
        "service": "http",
        "contains": "nginx",
        "severity": "info",
        "label": "Nginx Server Detected",
        "type": "fingerprint",
        "advice": "Nginx detected. Ensure it is kept up to date.",
        "cve": None,
    },
    {
        "service": "http",
        "contains": "nginx/1.18",
        "severity": "medium",
        "label": "Older Nginx Version",
        "type": "version_risk",
        "advice": "Nginx 1.18 detected. Review patch level and update if needed.",
        "cve": "CVE-2021-23017",
    },
    {
    "service": "http",
    "contains": "lighttpd",
    "severity": "info",
    "label": "Lighttpd Web Server Detected",
    "type": "fingerprint",
    "advice": "Lighttpd detected. Ensure it is kept updated and secured.",
    "cve": None,
    },
    {
    "service": "domain",
    "severity": "low",
    "label": "DNS Service Detected",
    "type": "network_service",
    "advice": "DNS is reachable. This is normal for routers, but should not be exposed unnecessarily.",
    "cve": None,
    },
    {
    "service": "tcpwrapped",
    "severity": "info",
    "label": "Filtered or Wrapped Service",
    "type": "access_control",
    "advice": "This port appears protected or wrapped. It may be limiting direct service detection.",
    "cve": None,
    },

    # Databases
    {
        "service": "mysql",
        "severity": "medium",
        "label": "MySQL Database Reachable",
        "type": "database_exposure",
        "advice": "Database should not be exposed. Restrict access to trusted devices.",
        "cve": None,
    },
    {
        "service": "postgresql",
        "severity": "medium",
        "label": "PostgreSQL Database Reachable",
        "type": "database_exposure",
        "advice": "Restrict database access to internal systems only.",
        "cve": None,
    },

    # Network services
    {
        "service": "upnp",
        "severity": "medium",
        "label": "UPnP Service Detected",
        "type": "network_exposure",
        "advice": "UPnP can open ports automatically. Disable if not needed.",
        "cve": None,
    },
    {
        "service": "snmp",
        "severity": "medium",
        "label": "SNMP Service Detected",
        "type": "network_management",
        "advice": "Use SNMPv3 or restrict access to prevent information leaks.",
        "cve": None,
    },
]
VULN_SCORE = {"low": 1, "medium": 3, "high": 6, "critical": 10}
COMMON_PORTS = list(range(1, 1025))
SNEAKY_PORTS = [
    1433, 1521, 1723, 1883, 1900, 2049,
    2375, 2376, 3000, 3306, 3389, 5000,
    5432, 5601, 5900, 5985, 6379, 8000,
    8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017,
    32400, 49152, 49153, 49154
]
DEFAULT_PORT_LIST = sorted(set(COMMON_PORTS + SNEAKY_PORTS))



def validate_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def get_local_networks() -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []

    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if addr.address == "127.0.0.1" or not addr.netmask:
                continue
            try:
                networks.append(ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False))
            except ValueError:
                continue

    return networks


def is_local_target(ip: str) -> bool:
    canonical_ip = format_ip(ip)
    if not canonical_ip:
        return False

    target = ipaddress.IPv4Address(canonical_ip)
    return any(target in network for network in get_local_networks())


def filter_allowed_devices(devices: Any) -> List[Dict[str, Any]]:
    if not isinstance(devices, list):
        return []

    allowed = []
    for device in devices:
        if not isinstance(device, dict):
            continue

        ip = format_ip(device.get("ip"))
        if not ip or not is_local_target(ip):
            continue

        cleaned = dict(device)
        cleaned["ip"] = ip
        cleaned["mac"] = format_mac(device.get("mac"))
        allowed.append(cleaned)

    return allowed


#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------

def get_local_device_type():
    try:
        output = subprocess.check_output(
            ["wmic", "computersystem", "get", "PCSystemType"],
            stderr=subprocess.DEVNULL
        ).decode()

        if "2" in output:
            return "laptop"
        if "1" in output:
            return "desktop"

    except Exception:
        pass

    return "device"

# Perform a reverse DNS lookup with a shared thread pool 
def reverseDNS_lookup(ip: str) -> Optional[str]:
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# Sends a single ping request and converts the response time to milliseconds.
def scan_latency(ip_addr: str) -> Optional[int]:
    try:
        latency = ping(ip_addr, timeout=1)
        return int(latency * 1000) if latency else None
    except Exception:
        return None
    
# Classify a device type based on its vendor name or hostname.
def classify_device(vendor: str, hostname: str) -> str:
    vendor = (vendor or "").replace("-", " ").lower()
    hostname = (hostname or "").lower()

    if (
        "laptop" in hostname
        or "desktop" in hostname
        or "pc" in hostname
        or "workstation" in hostname
        or "surface" in hostname
        or "macbook" in hostname
    ):
        return "laptop"
    if "dsldevice" in hostname:
        return "isp_gateway"
    
    for key, dtype in VENDOR_MAP:
        if key in vendor:
            return dtype

    if "router" in hostname or "gateway" in hostname:
        return "router"
    if "printer" in hostname:
        return "printer"
    if "camera" in hostname or "cam" in hostname:
        return "camera"
    if "tv" in hostname or "roku" in hostname:
        return "tv"
    if "console" in hostname or "xbox" in hostname or "playstation" in hostname:
        return "console"
    if "iot" in hostname or "esp" in hostname:
        return "iot"
    if "phone" in hostname or hostname.startswith("iphone") or "android" in hostname:
        return "phone"

    return "device"

# Lookup OUI from an api
def lookup_mac_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"

    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            return response.text.strip()
        return "Unknown"
    except Exception:
        return "Unknown"

@api.route("/latency/<ip>", methods=["GET"])
def get_latency(ip):
    ip = format_ip(ip)
    if not ip or not is_local_target(ip):
        return jsonify({"error": "Invalid IP"}), 400

    latency = scan_latency(ip)
    return jsonify({"ip": ip, "latency": latency})

# List available network interfaces on the system.
@api.route("/interfaces", methods=["GET"])
def list_interfaces():
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        if name.lower().startswith(("lo", "loopback")):
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                interfaces.append(
                    {"iface": name, "desc": name, "ip": addr.address, "netmask": addr.netmask}
                )
    return jsonify(interfaces)

# Scan a network interface and return discovered devices
# Enriches device data and includes scan status + history

@api.route("/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    iface = data.get("iface")

    if iface not in psutil.net_if_addrs():
        return jsonify({"error": "Unknown interface"}), 400

    # Extract Ipv4 + netmask from interface
    ip = netmask = None
    for addr in psutil.net_if_addrs()[iface]:
        if addr.family == socket.AF_INET:
            ip, netmask = addr.address, addr.netmask
            break
    if not ip or not netmask:
        return jsonify({"error": "No IPv4 address on interface"}), 400

     # Build the network range from IP/netmask
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    network_key = str(net)
    max_workers = int(os.environ.get("MAX_WORKERS", "20"))

    # Run base network scan from scanner.py
    try:
        devices = scan_network(ip, netmask, iface)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    local_type = get_local_device_type()

    # Enrich devices with data
    def enrich_device(d: Dict[str, Any]) -> Dict[str, Any]:
        mac = format_mac(d.get("mac"))
        ip_addr = format_ip(d.get("ip"))
        if not ip_addr:
            return {}
        hostname = reverseDNS_lookup(ip_addr)
        vendor = parser.get_manuf(mac) if mac else None

        if not vendor and mac:
            vendor = lookup_mac_vendor(mac)

        vendor = vendor or "Unknown"
        
        latency = scan_latency(ip_addr)
        insights: Dict[str, Any] = {}
        device_type = classify_device(vendor, hostname)

        if ip_addr == ip:
            device_type = local_type

        return {
            "ip": ip_addr,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "latency": latency,
            "type": device_type,
            "insights": insights,
        }
    # Run enrich_device in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = [device for device in executor.map(enrich_device, devices) if device.get("ip")]

    # Save scan + compare with previous results
    scan_results = save_scan_results(
        results,
        network=network_key,
        iface=iface,
        ip=ip,
        netmask=netmask,
    )

    # Get the status of each device from the scan results and attach to device
    status_map = scan_results.get("statuses", {})

    for entry in results:
        mac_key = f"mac:{format_mac(entry.get('mac'))}" if entry.get("mac") else None
        ip_key = f"ip:{entry['ip']}" if entry.get("ip") else None

        # try mac first because ip can change more frequently
        meta = {}
        if mac_key:
            meta = status_map.get(mac_key, {})
        if not meta and ip_key:
            meta = status_map.get(ip_key, {})

        entry["status"] = meta.get("status", "unknown")
        entry["changes"] = meta.get("changes", {})
        entry["device_id"] = meta.get("device_id")

    response = {
        "devices": results,
        "session_id": scan_results.get("session_id"),
        "summary": scan_results.get("summary", {}),
        "network": network_key,
        "iface": iface,
    }

    return jsonify(response)


#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------               

# Determine the network gateway and connect device-to-gateway topology links

@api.route("/topology-links", methods=["POST"])
def topology_links():
    data = request.get_json(force=True, silent=True) or {}

    raw_devices = data.get("devices", [])
    devices = []
    if isinstance(raw_devices, list):
        for device in raw_devices:
            if not isinstance(device, dict):
                continue
            cleaned = dict(device)
            cleaned["ip"] = format_ip(device.get("ip"))
            if cleaned["ip"]:
                devices.append(cleaned)
    source = format_ip(data.get("source"))

    if not source:
        return jsonify({"links": [], "gateway_ip": None})

    gateway_ip = None

    # prefer ISP gateway first
    for device in devices:
        ip = str(device.get("ip", "")).strip()
        dtype = (device.get("type") or "").lower()
        hostname = (device.get("hostname") or "").lower()

        if not validate_ip(ip):
            continue

        if dtype == "isp_gateway" or "dsldevice" in hostname:
            gateway_ip = ip
            break

    # Try common gateway IPs: .254 first, then .1
    if not gateway_ip:
        for preferred_suffix in [".254", ".1"]:
            for device in devices:
                ip = str(device.get("ip", "")).strip()

                if not validate_ip(ip):
                    continue

                if ip.endswith(preferred_suffix):
                    gateway_ip = ip
                    break

            if gateway_ip:
                break

    # If no common gateway IP then use router type/hostname
    if not gateway_ip:
        for device in devices:
            ip = str(device.get("ip", "")).strip()
            dtype = (device.get("type") or "").lower()
            hostname = (device.get("hostname") or "").lower()

            if not validate_ip(ip):
                continue

            if dtype == "router" or "gateway" in hostname or "router" in hostname:
                gateway_ip = ip
                break

    # If no gateway/router found then use host device ip
    if not gateway_ip:
        gateway_ip = source

    links = []

    for device in devices:
        ip = str(device.get("ip", "")).strip()

        if not validate_ip(ip):
            continue

        if ip == gateway_ip:
            continue

        links.append({
            "from_ip": gateway_ip,
            "to_ip": ip,
        })

    return jsonify({
        "links": links,
        "gateway_ip": gateway_ip
    })

#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------

# Run basic health checks on scanned devices

@api.route("/health-check", methods=["POST"])
def health_check():
    data = request.get_json(force=True)
    devices = filter_allowed_devices(data.get("devices", []))
    source_ip = format_ip(data.get("source"))
    # error hadle and valadate ip
    if not devices:
        return jsonify({"error": "Provide local-subnet devices from a scan."}), 400
    sampled_devices = devices

    # common ports to check for quick health check
    well_known_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995]

    health_results = {}
    port_results = {}

    workers = min(len(sampled_devices), 6) if sampled_devices else 1

    # Run latency checks and port scans in parallel
    with ThreadPoolExecutor(max_workers=workers) as executor:
        latency_futures = {
            executor.submit(scan_latency, d.get("ip")): d
            for d in sampled_devices
        }
        port_futures = {
            executor.submit(
                scan_ports_for_device,
                d.get("ip"),
                d.get("mac"),
                d.get("device_id"),
                well_known_ports
            ): d
            for d in sampled_devices
        }

        # Process latency results
        for future in as_completed(latency_futures):
            device = latency_futures[future]
            ip = device.get("ip")

            try:
                latency = future.result()
                health_results[ip] = {
                    "reachable": latency is not None,
                    "latency": latency
                }
            except Exception:
                health_results[ip] = {
                    "reachable": False,
                    "latency": None
                }

        # Process port scan results
        for future in as_completed(port_futures):
            device = port_futures[future]
            ip = device.get("ip")

            try:
                port_results[ip] = future.result()
            except Exception:
                port_results[ip] = {
                    "ip": ip,
                    "open_ports": [],
                    "risk": None,
                }

    return jsonify({
        "health_results": health_results,
        "port_results": port_results,
        "source": source_ip
    })

#----------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#----------------------------------------------------------------------------------

# Match open ports/services against known vulnerability patterns
def infer_vulnerabilities(port_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    service = (port_entry.get("service") or "").lower()
    banner = (port_entry.get("banner") or "").lower()
    port = port_entry.get("port")

    for rule in VULN_SIGNATURES:
        # Match by detected service name
        if rule.get("service") and rule["service"] not in service:
            continue
        # Match banner text
        contains = rule.get("contains")
        if contains and contains not in banner:
            continue

        findings.append({
            "label": rule.get("label"),
            "type": rule.get("type"),
            "cve": rule.get("cve"),
            "severity": rule.get("severity", "low"),
            "advice": rule.get("advice"),
            "port": port,
        })

    return findings

# Calculates the overall risk score from the vulnerability findings
def score_vulnerabilities(findings):
    seen = set()
    score = 0

    for finding in findings:
        key = f"{finding.get('label')}:{finding.get('port')}"
        if key in seen:
            continue
        seen.add(key)

        score += VULN_SCORE.get(finding.get("severity", "low"), 1)

    return score

# Clean and format the list of ports to scan
def get_ports(requested_ports):

    # use default ports if none provided
    if requested_ports is None:
        return DEFAULT_PORT_LIST

    ports = []

    # allow comma-separated string or list input
    if isinstance(requested_ports, str):
        requested_ports = requested_ports.split(",")
    try:
        for item in requested_ports:
            item = str(item).strip()

            if not item:
                continue

            if "-" in item:
                start_text, end_text = item.split("-", 1)

                try:
                    start = int(start_text.strip())
                    end = int(end_text.strip())
                except ValueError:
                    continue

                # swap if range is reversed
                if start > end:
                    start, end = end, start
                # Add all valid ports in range
                for port in range(start, end + 1):
                    if 1 <= port <= 65535:
                        ports.append(port)

            else:
                # for single port check
                try:
                    port = int(item)
                except ValueError:
                    continue

                if 1 <= port <= 65535:
                    ports.append(port)

    except TypeError:
        return []

    ports = sorted(set(ports))

    if not ports:
        return []
    # Im keeping the limit to 1024 at a time just to prevent long scan times (might change)
    return ports[:1024]

# Run Nmap scan on a device and return open ports + risk analysis
def scan_ports_for_device(ip, mac=None, device_id=None, requested_ports=None):
    ports = get_ports(requested_ports)

    if not ports:
        return {"ip": ip, "open_ports": [], "risk": None}
    if not validate_ip(ip):
        return {"ip": ip, "open_ports": [], "risk": None}
    nmap_bin = os.environ.get("NMAP_BIN", "nmap")
    if not shutil.which(nmap_bin):
        raise RuntimeError("Nmap is not installed")

    # build nmap command with specified ports and XML output/  used light version for faster scans 
    port_str = ",".join(str(int(p)) for p in ports)
    cmd = [nmap_bin, "-sV", "--version-light", "-p", port_str, ip, "-oX", "-"]
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=90)
    root = ET.fromstring(output)

    ports_info = []
    all_findings = []
    # need to parse the nmap xml and extract only open ports
    for port in root.findall(".//port"):
        state = port.find("state")
        # check if open
        if state is None or state.get("state") != "open":
            continue

        port_id = int(port.get("portid"))
        service = port.find("service")
        # Default values
        name = "unknown"
        banner = ""

        if service is not None:
            # get service name
            name = service.get("name") or name
            # build banner from product, version, extrainfo
            product = service.get("product") or ""
            version = service.get("version") or ""
            extrainfo = service.get("extrainfo") or ""
            banner = " ".join(x for x in [product, version, extrainfo] if x).strip()

        # Build the port entry and infer vulnerabilities
        entry = {"port": port_id, "service": name, "banner": banner}
        findings = infer_vulnerabilities(entry)
        if findings:
            entry["vulnerabilities"] = findings
            all_findings.extend(findings)

        ports_info.append(entry)
    # get vulnerability score
    exposure_score = score_vulnerabilities(all_findings)

    risk_label = "low"
    if exposure_score >= 20:
        risk_label = "critical"
    elif exposure_score >= 12:
        risk_label = "high"
    elif exposure_score >= 6:
        risk_label = "medium"

    # Last persist scan results and return response to frontend
    save_ports_for_ip(
        ip=ip,
        mac=mac,
        device_id=device_id,
        ports=ports_info,
        scanned_ports=ports,
    )

    return {
        "ip": ip,
        "open_ports": ports_info,
        "risk": {
            "score": exposure_score,
            "label": risk_label,
            "findings": all_findings,
        },
    }

# Scan a device for open TCP ports using Nmap
# Returns services, banners, and risk summary

@api.route("/scan-ports", methods=["POST"])
def scan_ports():
    data = request.get_json(force=True)
    target_ip = format_ip(data.get("ip"))

    if not target_ip or not is_local_target(target_ip):
        return jsonify({"error": "Target IP must be on a local interface subnet."}), 400

    try:
        result = scan_ports_for_device(
            ip=target_ip,
            mac=data.get("mac"),
            device_id=data.get("device_id"),
            requested_ports=data.get("ports"),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------

# Scan devices for SMB shares (port 445)
# Returns IPs with available shares.

def list_smb_shares(ip: str) -> List[str]:
    if not validate_ip(ip):
        return []
    # send smb command
    try:
        out = subprocess.check_output(
            ["net", "view", f"\\\\{ip}"],
            stderr=subprocess.DEVNULL,   # hide errors
            timeout=10
        )
        text = out.decode(errors="ignore")

        shares = []
        for line in text.splitlines():
            if "Disk" in line or "Printer" in line:  # Find lines that indicate shares
                parts = line.split()
                if parts:
                    shares.append(parts[0])

        return shares

    except Exception:
        return []

@api.route("/scan-drives", methods=["POST"])
def scan_drives():
    data = request.get_json(force=True)
    devices = filter_allowed_devices(data.get("devices", []))
    results = []
    # Create the port check
    def port445_check(ip, port=445, timeout=0.7):
        import socket as _socket

        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                return sock.connect_ex((ip, port)) == 0
            except Exception:
                return False

    for device in devices:
        ip = device.get("ip")

        if not ip or not validate_ip(ip):
            continue
            # call pot check
        if not port445_check(ip, port=445, timeout=float(os.environ.get("SMB_TIMEOUT", "0.3"))):
            continue
        # Get the list of shares for the device
        shares = list_smb_shares(ip)
        results.append({
            "ip": ip,
            "shares": shares
        })

    return jsonify({"drives": results})

#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------

# Return recent network scan history to frontend (models.py)

@api.route("/scan-history", methods=["GET"])
def scan_history():
    try:
        limit = int(request.args.get("limit", 12))
    except (TypeError, ValueError):
        limit = 12

    limit = max(1, min(limit, 50))
    return jsonify({"history": get_recent_scans(limit=limit)})


# Return device snapshots for a specific scan session (models.py)

@api.route("/scan-history/<int:session_id>", methods=["GET"])
def scan_history_detail(session_id: int):
    snapshots = get_session_snapshots(session_id)

    if not snapshots:
        return jsonify({"error": "Session not found"}), 404

    return jsonify(snapshots)

#---------------------------------------------------------------------------------
#ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
#---------------------------------------------------------------------------------

# Analyze network scan results Ollama AI model.

@api.route("/analyze", methods=["POST"])
def analyze_with_ollama():

    data = request.get_json(force=True)
    devices = data.get("devices", [])
    question = data.get("question", "Summarize the network’s current state.")

    if not devices:
        return jsonify({"error": "No devices provided"})
    
    # Create a prompt for the model
    summary = "\n".join([
        f"IP: {d.get('ip')}, MAC: {d.get('mac')}, Vendor: {d.get('vendor', 'Unknown')}, "
        f"Type: {d.get('type', 'Unknown')}, Latency: {d.get('latency', 'N/A')}ms, "
        f"Open Ports: {d.get('open_ports', 'Unknown')}"
        for d in devices
    ])

    # Prompt for ollama to analyze
    prompt = f"""
        You are a home/small business network assistant.

        Analyze this network scan summary using only the provided data.
        Do not invent vulnerabilities.
        If open ports are listed, explain the possible concern in simple terms.
        If no open ports are listed, say port scan data is not available.

        Network data:
        {summary}

        User question:
        {question}

        Respond in this format:

        Network Health:
        - <simple summary>

        Possible Concerns:
        - <open ports, unknown devices, high latency, or exposed sharing>

        Suggested Next Steps:
        - <simple practical steps>

        Each section should be seperated by a new line, start with the header bolded and a dash followed by your analysis.
        """

    try:
        response = ollama.chat(model="llama3.2:1b", messages=[
            {"role": "user", "content": prompt}
        ])
        result = response["message"]["content"]
    except Exception as error:
        result = f"Error connecting to Ollama: {error}"

    return jsonify({"analysis": result})
