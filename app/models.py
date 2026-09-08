# app/models.py

import ipaddress
import re
import socket
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import json
from typing import Optional, Dict, Any, List, Set, Tuple
from sqlalchemy import create_engine, Column, Integer, String, DateTime, UniqueConstraint, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship


connect_uri = "sqlite:///netscope.db"
engine = create_engine(
    connect_uri,
    connect_args={"check_same_thread": False}, 
    future=True,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base = declarative_base()
def format_mac(value: Optional[str]) -> Optional[str]:
    raw = (value or "").strip().lower()
    if not raw:
        return None

    hex_chars = re.sub(r"[^0-9a-f]", "", raw)
    if len(hex_chars) != 12:
        return None

    return ":".join(hex_chars[i:i + 2] for i in range(0, 12, 2))


def format_ip(value: Optional[str]) -> Optional[str]:
    raw = (value or "").strip()
    if not raw:
        return None

    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


# db tables
class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), index=True)
    mac = Column(String(32), index=True, nullable=True)
    hostname = Column(String(255))
    vendor = Column(String(255))
    dtype = Column(String(50))
    latency = Column(Integer)
    last_seen = Column(DateTime, default=datetime.now, index=True)
    snapshots = relationship("DeviceSnapshot", back_populates="device", cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint("ip", "mac", name="uq_devices_ip_mac"),)

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, default=datetime.now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # NEW: identify which network/subnet this scan belongs to (Plan A)
    network = Column(String(64), index=True, nullable=True)  # ex: "192.168.1.0/24"
    iface = Column(String(64), nullable=True)                # ex: "Ethernet"
    ip = Column(String(64), nullable=True)                   # ex: "192.168.1.34"
    netmask = Column(String(64), nullable=True)              # ex: "255.255.255.0"

    device_total = Column(Integer, default=0)
    new_devices = Column(Integer, default=0)
    updated_devices = Column(Integer, default=0)
    offline_devices = Column(Integer, default=0)

    snapshots = relationship("DeviceSnapshot", back_populates="session", cascade="all, delete-orphan")

class DeviceSnapshot(Base):
    __tablename__ = "device_snapshots"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    ip = Column(String(45))
    mac = Column(String(32), nullable=True)
    hostname = Column(String(255))
    vendor = Column(String(255))
    dtype = Column(String(50))
    latency = Column(Integer, nullable=True)
    status = Column(String(32), nullable=False)  # new, updated, unchanged, offline
    changes = Column(Text, nullable=True)
    extra = Column(Text, nullable=True)
    recorded_at = Column(DateTime, default=datetime.now, nullable=False)

    session = relationship("ScanSession", back_populates="snapshots")
    device = relationship("Device", back_populates="snapshots")

class DevicePort(Base):
    __tablename__ = "device_ports"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), index=True, nullable=False)
    mac = Column(String(32), index=True, nullable=True)
    protocol = Column(String(8), default="tcp", nullable=False)
    port = Column(Integer, nullable=False)
    service = Column(String(128))
    banner = Column(String(255))
    last_seen = Column(DateTime, default=datetime.now, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    __table_args__ = (
        UniqueConstraint("ip", "protocol", "port", name="uq_ports_ip_proto_port"),
    )


# create db and table if not exist
def init_db() -> None:
    Base.metadata.create_all(engine)

# Save scan results and track device changes and status for the session
def save_scan_results(
    scanned_devices: List[Dict[str, Any]],
    network: str = None,
    iface: str = None,
    ip: str = None,
    netmask: str = None,
) -> Dict[str, Any]:
    
    db = SessionLocal()
    scan_time = datetime.now()

    try:
        # Create scan session
        scan_session = ScanSession(started_at=scan_time)

        session_metadata = {
            "network": network,
            "iface": iface,
            "ip": ip,
            "netmask": netmask,
        }

        for field, value in session_metadata.items():
            if value is not None and hasattr(scan_session, field):
                setattr(scan_session, field, value)

        db.add(scan_session)
        db.flush()

        # Load existing (known) devices
        network_filter = None

        if network:
            try:
                network_filter = ipaddress.ip_network(network, strict=False)
            except Exception:
                network_filter = None

        all_known_devices = db.query(Device).all()

        known_devices: List[Any] = []
        known_by_mac: Dict[str, Any] = {}
        known_by_ip: Dict[str, List[Any]] = {}

        for known in all_known_devices:
            # Filter by network if needed
            if network_filter and known.ip:
                try:
                    if ipaddress.ip_address(known.ip) not in network_filter:
                        continue
                except Exception:
                    continue

            known_devices.append(known)

            mac_key = format_mac(known.mac)
            if mac_key:
                known_by_mac[mac_key] = known

            if known.ip:
                known_by_ip.setdefault(known.ip, []).append(known)

        seen_device_ids: Set[int] = set()
        processed_scan_keys: Set[Tuple[str, Optional[str]]] = set()
        device_status_log: List[Dict[str, Any]] = []

        # Process scanned devices
        for scan_result in scanned_devices:
            formated_data = build_device_from_payload(scan_result)

            mac = formated_data["mac"]
            ip_addr = formated_data["ip"]

            if not mac and not ip_addr:
                continue

            # Try MAC first as identifier
            unique_key = ("mac", mac) if mac else ("ip", ip_addr)

            if unique_key in processed_scan_keys:
                continue

            processed_scan_keys.add(unique_key)

            # Try to match with known device
            device = find_existing_device(
                known_by_mac,
                known_by_ip,
                scan_result
            )

            status = "new"
            changes: Dict[str, Dict[str, Any]] = {}

            # Create new device if no match
            if device is None:
                device = Device(**formated_data, last_seen=scan_time)

                try:
                    with db.begin_nested():
                        db.add(device)
                        db.flush()

                except IntegrityError:
                    device = find_existing_device(
                        known_by_mac,
                        known_by_ip,
                        scan_result
                    )

                    if device is None and mac:
                        device = db.query(Device).filter(Device.mac == mac).first()

                    if device is None and ip_addr:
                        device = (
                            db.query(Device)
                            .filter(Device.ip == ip_addr, Device.mac.is_(None))
                            .first()
                        )

                    if device is None:
                        continue

                    status = "unchanged"
            else:
                status = "unchanged"

            # Create a Snapshot of device before changes
            before_state = device_snapshot(device)

            # Fill missing MAC if possible
            if mac and not format_mac(device.mac):
                existing_owner = (
                    db.query(Device)
                    .filter(Device.mac == mac, Device.id != device.id)
                    .first()
                )

                if not existing_owner:
                    device.mac = mac

            # Update changed fields
            fields = ["ip", "hostname", "vendor", "dtype", "latency"]
            for field in fields:
                new_val = formated_data.get(field)
                old_val = getattr(device, field)

                if new_val is not None and old_val != new_val:
                    changes[field] = {
                        "before": old_val,
                        "after": new_val,
                    }
                    setattr(device, field, new_val)

            # Catch any missed changes
            for field, old_val in before_state.items():
                new_val = getattr(device, field)

                if field not in changes and new_val != old_val:
                    changes[field] = {
                        "before": old_val,
                        "after": new_val,
                    }

            if status != "new" and changes:
                status = "updated"

            device.last_seen = scan_time
            db.flush()

            if device.id:
                seen_device_ids.add(device.id)

            # Update lookup maps
            mac_key = format_mac(device.mac)

            if mac_key:
                known_by_mac[mac_key] = device

            if device.ip:
                same_ip_devices = known_by_ip.setdefault(device.ip, [])

                if all(d.id != device.id for d in same_ip_devices):
                    same_ip_devices.append(device)

            # Save snapshot
            snapshot = DeviceSnapshot(
                session=scan_session,
                device=device,
                status=status,
                ip=device.ip,
                mac=device.mac,
                hostname=device.hostname,
                vendor=device.vendor,
                dtype=device.dtype,
                latency=device.latency,
                changes=json.dumps(changes, default=str) if changes else None,
                extra=json.dumps(scan_result.get("insights"), default=str)
                if scan_result.get("insights")
                else None,
            )

            db.add(snapshot)

            device_status_log.append({
                "device_id": device.id,
                "ip": device.ip,
                "mac": device.mac,
                "status": status,
                "changes": changes,
            })

        # 5. Mark unseen devices as OFFLINE
        for known in known_devices:
            if known.id in seen_device_ids:
                continue

            snapshot = DeviceSnapshot(
                session=scan_session,
                device=known,
                status="offline",
                ip=known.ip,
                mac=known.mac,
                hostname=known.hostname,
                vendor=known.vendor,
                dtype=known.dtype,
                latency=known.latency,
                changes=None,
            )

            db.add(snapshot)

            device_status_log.append({
                "device_id": known.id,
                "ip": known.ip,
                "mac": known.mac,
                "status": "offline",
                "changes": {},
            })

        # 6. Summary
        scan_session.device_total = len(processed_scan_keys)
        scan_session.new_devices = sum(d["status"] == "new" for d in device_status_log)
        scan_session.updated_devices = sum(d["status"] == "updated" for d in device_status_log)
        scan_session.offline_devices = sum(d["status"] == "offline" for d in device_status_log)
        scan_session.completed_at = datetime.now()

        db.commit()

        # Build the response
        status_lookup = {}

        for entry in device_status_log:
            if entry["mac"]:
                key = f"mac:{format_mac(entry['mac'])}"
            elif entry["ip"]:
                key = f"ip:{entry['ip']}"
            else:
                key = f"device:{entry['device_id']}"

            status_lookup[key] = {
                "status": entry["status"],
                "changes": entry["changes"],
                "device_id": entry["device_id"],
            }

        return {
            "session_id": scan_session.id,
            "statuses": status_lookup,
            "summary": {
                "total": scan_session.device_total,
                "new": scan_session.new_devices,
                "updated": scan_session.updated_devices,
                "offline": scan_session.offline_devices,
            },
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

# Get basic device details for a snapshot
def device_snapshot(device: Any) -> Dict[str, Any]:
    return {
        "hostname": device.hostname,
        "vendor": device.vendor,
        "dtype": device.dtype,
        "latency": device.latency,
    }

# Build a clean device record from scan data
def build_device_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ip": format_ip(payload.get("ip")),
        "mac": format_mac(payload.get("mac")),
        "hostname": payload.get("hostname"),
        "vendor": payload.get("vendor"),
        "dtype": payload.get("type"),
        "latency": payload.get("latency"),
    }

# Find an existing device by matching mac first then ip when safe
def find_existing_device(
    baseline_by_mac: Dict[str, Any],
    baseline_by_ip: Dict[str, List[Any]],
    payload: Dict[str, Any],
) -> Optional[Any]:
    
    mac_val = format_mac(payload.get("mac"))
    ip_val = format_ip(payload.get("ip"))

    # Try to match mac first
    if mac_val:
        device = baseline_by_mac.get(mac_val)
        if device is not None:
            return device

    # Fallback IP, but only if the macs do not conflict
    if ip_val:
        ip_matches = baseline_by_ip.get(ip_val, [])
        if not ip_matches:
            return None

        # If payload has a MAC then only allow ip_matches with same MAC or no MAC
        if mac_val:
            for device in ip_matches:
                existing_mac = format_mac(device.mac)
                if existing_mac == mac_val:
                    return device
            for device in ip_matches:
                existing_mac = format_mac(device.mac)
                if not existing_mac:
                    return device
            return None

        # If payload has no MAC then prefer a device with no MAC
        for device in ip_matches:
            existing_mac = format_mac(device.mac)
            if not existing_mac:
                return device

        return None

    return None

# Save open ports for an IP and remove closed ports from the last scan
def save_ports_for_ip(
    *,
    ip: str,
    ports: List[Dict[str, Any]],
    mac: Optional[str],
    device_id: Optional[int] = None,
    protocol: str = "tcp",
    scanned_ports: Optional[List[int]] = None
) -> None:
    session = SessionLocal()
    try:
        now = datetime.now()
        formated_mac = format_mac(mac)
        open_ports = {p.get("port") for p in ports if isinstance(p.get("port"), int)}

        for entry in ports:
            port_number = entry.get("port")
            if not isinstance(port_number, int):
                continue

            service = entry.get("service")
            banner = entry.get("banner")
            record = None

            if device_id is not None:
                record = (
                    session.query(DevicePort)
                    .filter_by(device_id=device_id, protocol=protocol, port=port_number)
                    .first()
                )

            if record is None and formated_mac:
                record = (
                    session.query(DevicePort)
                    .filter_by(mac=formated_mac, protocol=protocol, port=port_number)
                    .first()
                )

            if record is None:
                record = (
                    session.query(DevicePort)
                    .filter_by(ip=ip, protocol=protocol, port=port_number)
                    .first()
                )

            if record:
                record.service = service or record.service
                record.banner = banner or record.banner
                record.ip = ip or record.ip
                record.mac = formated_mac or record.mac
                record.device_id = device_id if device_id is not None else record.device_id
                record.last_seen = now
            else:
                record = DevicePort(
                    ip=ip,
                    mac=formated_mac,
                    device_id=device_id,
                    protocol=protocol,
                    port=port_number,
                    service=service,
                    banner=banner,
                    last_seen=now,
                )
                session.add(record)

        if scanned_ports:
            scanned_set = {p for p in scanned_ports if isinstance(p, int)}
            if scanned_set:
                delete_query = session.query(DevicePort).filter(
                    DevicePort.protocol == protocol,
                    DevicePort.port.in_(scanned_set),
                    DevicePort.port.notin_(open_ports),
                )

                if device_id is not None:
                    delete_query = delete_query.filter(DevicePort.device_id == device_id)
                else:
                    delete_query = delete_query.filter(DevicePort.ip == ip)

                delete_query.delete(synchronize_session=False)

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def socket_endpoint(endpoint: Any) -> Tuple[Optional[str], Optional[int]]:
    if not isinstance(endpoint, tuple) or not endpoint:
        return None, None

    ip = format_ip(str(endpoint[0]))
    port = endpoint[1] if len(endpoint) > 1 and isinstance(endpoint[1], int) else None
    return ip, port

def peek_socket_payload(client_socket: Any, max_bytes: int = 1024, timeout: float = 0.2) -> Optional[str]:
    previous_timeout = None
    try:
        previous_timeout = client_socket.gettimeout()
        client_socket.settimeout(timeout)
        data = client_socket.recv(max_bytes, socket.MSG_PEEK)
    except (BlockingIOError, TimeoutError, socket.timeout):
        return None
    except OSError:
        return None
    finally:
        try:
            client_socket.settimeout(previous_timeout)
        except OSError:
            pass

    if not data:
        return None

    return data.decode("utf-8", errors="replace")

def save_connection_data(client_socket, addr):
    session = SessionLocal()
    try:
        remote_ip, remote_port = socket_endpoint(addr)

        if not remote_ip:
            try:
                remote_ip, remote_port = socket_endpoint(client_socket.getpeername())
            except OSError:
                pass

        if not remote_ip:
            raise ValueError("Could not determine remote connection address")

        local_ip = None
        local_port = None
        try:
            local_ip, local_port = socket_endpoint(client_socket.getsockname())
        except OSError:
            pass

        payload_preview = peek_socket_payload(client_socket)
        connection = ConnectionLog(
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_ip=local_ip,
            local_port=local_port,
            payload_preview=payload_preview,
            extra=json.dumps({"addr": addr}, default=str),
        )

        session.add(connection)
        session.commit()
        return connection
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        
# Get most recent scan sessions up to a limit
def get_recent_scans(limit: int = 12) -> List[Dict[str, Any]]:
    
    session = SessionLocal()
    try:
        scans = (
            session.query(ScanSession)
            .order_by(ScanSession.started_at.desc())
            .limit(limit)
            .all()
        )
        history: List[Dict[str, Any]] = []
        for scan in scans:
            history.append(
                {
                    "id": scan.id,
                    "started_at": scan.started_at.isoformat(),
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "summary": {
                        "total": scan.device_total,
                        "new": scan.new_devices,
                        "updated": scan.updated_devices,
                        "offline": scan.offline_devices,
                    },
                }
            )
        return history
    finally:
        session.close()

# Get all saved device snapshots for one scan session
def get_session_snapshots(session_id: int) -> Dict[str, Any]:
    session = SessionLocal()
    try:
        scan = (
            session.query(ScanSession)
            .filter(ScanSession.id == session_id)
            .first()
        )

        if not scan:
            return {}

        snapshots = (
            session.query(DeviceSnapshot)
            .filter(DeviceSnapshot.session_id == session_id)
            .order_by(DeviceSnapshot.recorded_at.asc())
            .all()
        )

        response: List[Dict[str, Any]] = []

        for snap in snapshots:
            open_ports = get_ports_for_device(
                session,
                snap.device_id,
                snap.ip,
                snap.mac,
            )

            response.append(
                {
                    "device_id": snap.device_id,
                    "ip": snap.ip,
                    "mac": snap.mac,
                    "hostname": snap.hostname,
                    "vendor": snap.vendor,
                    "dtype": snap.dtype,
                    "latency": snap.latency,
                    "status": snap.status,
                    "changes": json.loads(snap.changes) if snap.changes else {},
                    "extra": json.loads(snap.extra) if snap.extra else {},
                    "open_ports": open_ports,
                    "recorded_at": snap.recorded_at.isoformat(),
                }
            )

        return {
            "session_id": scan.id,
            "session": {
                "ip": scan.ip,
                "iface": scan.iface,
                "network": scan.network,
                "netmask": scan.netmask,
            },
            "snapshots": response,
        }

    finally:
        session.close()

# Get ports for a device by checking id then mac then ip
def get_ports_for_device(
    session,
    device_id: Optional[int],
    ip: Optional[str],
    mac: Optional[str],
) -> List[Dict[str, Any]]:
    rows = []

    if device_id is not None:
        rows = (
            session.query(DevicePort)
            .filter(DevicePort.device_id == device_id)
            .order_by(DevicePort.port.asc())
            .all()
        )

    if not rows and mac:
        rows = (
            session.query(DevicePort)
            .filter(DevicePort.mac == format_mac(mac))
            .order_by(DevicePort.port.asc())
            .all()
        )

    if not rows and ip:
        rows = (
            session.query(DevicePort)
            .filter(DevicePort.ip == ip)
            .order_by(DevicePort.port.asc())
            .all()
        )

    return [
        {
            "port": row.port,
            "service": row.service or "unknown",
            "banner": row.banner or "",
        }
        for row in rows
    ]
