import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models as models


class SaveScanResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "test.db"
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            future=True,
        )
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

        self.original_engine = models.engine
        self.original_session_local = models.SessionLocal
        models.engine = self.engine
        models.SessionLocal = self.session_factory
        models.Base.metadata.create_all(self.engine)

    def tearDown(self):
        models.Base.metadata.drop_all(self.engine)
        self.engine.dispose()
        models.engine = self.original_engine
        models.SessionLocal = self.original_session_local
        self.temp_dir.cleanup()

    def count_devices(self):
        session = models.SessionLocal()
        try:
            return session.query(models.Device).count()
        finally:
            session.close()

    def get_devices(self):
        session = models.SessionLocal()
        try:
            return session.query(models.Device).order_by(models.Device.id.asc()).all()
        finally:
            session.close()

    def test_format_mac_canonicalizes_common_forms(self):
        self.assertEqual(models.format_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(models.format_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(models.format_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(models.format_mac("not-a-mac"))

    def test_mac_identity_survives_ip_change_and_updates_latency(self):
        first = models.save_scan_results(
            [
                {
                    "ip": "192.168.1.10",
                    "mac": "AA-BB-CC-DD-EE-FF",
                    "hostname": "laptop",
                    "vendor": "Dell",
                    "type": "laptop",
                    "latency": 12,
                }
            ],
            network="192.168.1.0/24",
        )
        second = models.save_scan_results(
            [
                {
                    "ip": "192.168.1.25",
                    "mac": "aabb.ccdd.eeff",
                    "hostname": "laptop",
                    "vendor": "Dell",
                    "type": "laptop",
                    "latency": 34,
                }
            ],
            network="192.168.1.0/24",
        )

        devices = self.get_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].ip, "192.168.1.25")
        self.assertEqual(devices[0].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(devices[0].latency, 34)
        self.assertEqual(first["summary"]["new"], 1)
        self.assertEqual(second["summary"]["updated"], 1)
        self.assertEqual(second["summary"]["offline"], 0)

    def test_ping_only_device_reuses_same_ip_without_duplicate_mac_null_rows(self):
        payload = {
            "ip": "192.168.1.40",
            "mac": None,
            "hostname": "ping-only",
            "vendor": "Unknown",
            "type": "device",
            "latency": 9,
        }

        first = models.save_scan_results([payload], network="192.168.1.0/24")
        second = models.save_scan_results([payload], network="192.168.1.0/24")

        self.assertEqual(self.count_devices(), 1)
        self.assertEqual(first["summary"]["new"], 1)
        self.assertEqual(second["summary"]["new"], 0)
        self.assertEqual(second["summary"]["offline"], 0)

    def test_offline_devices_are_scoped_to_the_scanned_network(self):
        models.save_scan_results(
            [{"ip": "192.168.1.10", "mac": None, "hostname": "home", "vendor": "Unknown", "type": "device"}],
            network="192.168.1.0/24",
        )

        result = models.save_scan_results(
            [{"ip": "10.0.0.10", "mac": None, "hostname": "lab", "vendor": "Unknown", "type": "device"}],
            network="10.0.0.0/24",
        )

        self.assertEqual(self.count_devices(), 2)
        self.assertEqual(result["summary"]["offline"], 0)

    def test_save_connection_data_records_socket_endpoints(self):
        class FakeSocket:
            def __init__(self):
                self.timeout = None

            def gettimeout(self):
                return self.timeout

            def settimeout(self, value):
                self.timeout = value

            def recv(self, max_bytes, flags):
                return b"hello from client"

            def getsockname(self):
                return ("192.168.1.5", 8080)

            def getpeername(self):
                return ("192.168.1.50", 54321)

        fake_socket = FakeSocket()
        connection = models.save_connection_data(fake_socket, ("192.168.1.50", 54321))

        session = models.SessionLocal()
        try:
            rows = session.query(models.ConnectionLog).all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].id, connection.id)
            self.assertEqual(rows[0].remote_ip, "192.168.1.50")
            self.assertEqual(rows[0].remote_port, 54321)
            self.assertEqual(rows[0].local_ip, "192.168.1.5")
            self.assertEqual(rows[0].local_port, 8080)
            self.assertEqual(rows[0].payload_preview, "hello from client")
            self.assertIsNone(fake_socket.timeout)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
