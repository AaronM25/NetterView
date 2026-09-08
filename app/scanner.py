# app/scanner.py

from typing import List, Dict, Optional
import ipaddress
import concurrent.futures
import socket
from scapy.all import ARP, Ether, srp
from ping3 import ping  


# Calculate subnet
def get_subnet(ip: str, netmask: str) -> str:
    iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    return str(iface.network)

def arp_sweep(subnet: str, iface: str, timeout: float = 1.5) -> List[Dict]:
    net = ipaddress.IPv4Network(subnet, strict=False)
    if net.num_addresses > 4096:
        raise ValueError("Subnet is too large to scan safely")

    # Create ARP Broadcast Packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Creates an ARP request for every IP in the subnet
    arp = ARP(pdst=subnet)
    # Send packets and collect ans
    ans, _ = srp(ether / arp, iface=iface, timeout=timeout, retry=1, inter=0.02, verbose=0)
    devices: List[Dict] = []
    for _, r in ans:
        devices.append({"ip": r.psrc, "mac": r.hwsrc})
    return devices



def ping_sweep(subnet: str, max_workers=64) -> List[Dict]:
    
    # Convert the subnet string into a network object
    net = ipaddress.IPv4Network(subnet, strict=False)
    # Create a list of all usable IP addresses in the subnet
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 4096:
        hosts = hosts[:4096]
    # Store responces
    results: List[Dict] = []

    def ping_one(addr: str) -> Optional[Dict]:
        try:
            r = ping(addr, timeout=0.25)
            return {"ip": addr, "mac": None} if r else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(ping_one, hosts):
            if res:
                results.append(res)
    return results

# Scan network (try arp first, ping fallback)
def scan_network(ip: str, netmask: str, iface: str,
                 timeout: float = 1.5,
                 max_workers: int = 64) -> List[Dict]:
    
    subnet = get_subnet(ip, netmask)

    # ARP sweep
    devices = arp_sweep(subnet, iface, timeout=timeout)
    

    # Ping fallback for anything ARP missed
    seen = {d["ip"] for d in devices}
    fallback = [d for d in ping_sweep(subnet, max_workers=max_workers) if d["ip"] not in seen]
    devices.extend(fallback)

    return devices
