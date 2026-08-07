#!/usr/bin/env python3
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_PY = os.path.join(HERE, "tamizdat-panel.py")


class PanelLocalTUNTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="tamizdat-panel-local-tun-")
        os.environ["TAMIZDAT_PANEL_DB"] = os.path.join(cls.tmpdir, "panel.db")
        os.environ["TAMIZDAT_PANEL_LEGACY_SHORTID"] = os.path.join(cls.tmpdir, "missing-shortid")
        os.environ["TAMIZDAT_PANEL_SERVER_PIDFILE"] = os.path.join(cls.tmpdir, "missing.pid")
        os.environ["TAMIZDAT_PANEL_EXPVAR_URL"] = ""
        cls.panel = SourceFileLoader("tamizdat_panel_local_tun", PANEL_PY).load_module()
        cls.panel._sighup_server = lambda: None
        cls.panel.ensure_db()

    def setUp(self):
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM users")

    def test_create_disabled_local_user_and_enable_with_interface(self):
        user = self.panel.create_user({
            "name": "router-lan",
            "user_kind": "local_tun",
            "local_enabled": False,
            "local_tun_name": "taml0",
            "local_tun_addr": "198.18.0.1/24",
            "local_tun_mtu": 1280,
            "local_auto_route": True,
            "local_bypass_private": True,
            "local_block_quic": True,
            "local_sniff": True,
        })
        self.assertEqual(user["user_kind"], "local_tun")
        self.assertFalse(user["local_enabled"])
        self.assertEqual(user["local_state"], "disabled")
        self.assertTrue(user["local_block_quic"])
        self.assertFalse(user["local_fail_closed"])

        with self.assertRaisesRegex(ValueError, "local_iface is required"):
            self.panel.update_user(user["id"], {"local_enabled": True})

        updated = self.panel.update_user(user["id"], {
            "user_kind": "local_tun",
            "local_enabled": True,
            "local_iface": "br-lan",
            "local_fail_closed": True,
        })
        self.assertTrue(updated["local_enabled"])
        self.assertEqual(updated["local_iface"], "br-lan")
        self.assertTrue(updated["local_fail_closed"])
        self.assertEqual(updated["outbound_tag"], "direct")

        ignored = self.panel.update_user(user["id"], {
            "user_kind": "local_tun",
            "outbound_tag": "does-not-exist",
        })
        self.assertEqual(ignored["outbound_tag"], "direct")

    def test_only_one_local_user_and_kind_is_immutable(self):
        user = self.panel.create_user({
            "name": "router-lan",
            "user_kind": "local_tun",
            "local_enabled": False,
        })
        with self.assertRaisesRegex(ValueError, "only one local TUN user"):
            self.panel.create_user({
                "name": "router-lan-2",
                "user_kind": "local_tun",
                "local_enabled": False,
            })
        with self.assertRaisesRegex(ValueError, "cannot be changed"):
            self.panel.update_user(user["id"], {"user_kind": "remote"})

    def test_remote_user_rejects_local_fields(self):
        with self.assertRaisesRegex(ValueError, "require user_kind=local_tun"):
            self.panel.create_user({
                "name": "remote",
                "user_kind": "remote",
                "local_enabled": True,
            })

    def test_schema_contains_local_tun_columns(self):
        with self.panel.db_conn() as con:
            cols = {row["name"] for row in con.execute("PRAGMA table_info(users)")}
            version = con.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()["value"]
        self.assertEqual(version, "13")
        self.assertTrue({
            "user_kind", "local_enabled", "local_iface", "local_tun_name",
            "local_tun_addr", "local_tun_mtu", "local_auto_route",
            "local_bypass_private", "local_block_quic", "local_sniff", "local_fail_closed",
        }.issubset(cols))
        with self.panel.db_conn() as con:
            indexes = {row["name"] for row in con.execute("PRAGMA index_list(users)")}
        self.assertIn("users_one_local_tun", indexes)

    def test_concurrent_local_user_creation_returns_domain_error(self):
        original = self.panel._new_unique_master_shortid
        barrier = threading.Barrier(2)

        def synchronized_shortid(con):
            value = original(con)
            barrier.wait(timeout=3)
            return value

        def create(index):
            try:
                return self.panel.create_user({
                    "name": f"router-lan-{index}",
                    "user_kind": "local_tun",
                    "local_enabled": False,
                })
            except Exception as exc:
                return exc

        with mock.patch.object(self.panel, "_new_unique_master_shortid", side_effect=synchronized_shortid):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(create, range(2)))
        users = [result for result in results if isinstance(result, dict)]
        errors = [result for result in results if isinstance(result, Exception)]
        self.assertEqual(len(users), 1, results)
        self.assertEqual(len(errors), 1, results)
        self.assertIsInstance(errors[0], ValueError)
        self.assertIn("only one local TUN user", str(errors[0]))


    def test_local_runtime_marks_running_and_uses_tun_counters(self):
        user = {
            "id": 1,
            "user_kind": "local_tun",
            "local_enabled": True,
            "local_state": "starting",
            "local_error": "",
            "bytes_down": 0,
            "bytes_up": 0,
        }
        runtime = {
            "local_state": "running",
            "local_error": "",
            "bytes_down": 123,
            "bytes_up": 456,
        }
        with mock.patch.object(self.panel, "_local_tun_runtime", return_value=runtime):
            merged = self.panel._merge_local_tun_runtime([user])
        self.assertEqual(merged[0]["local_state"], "running")
        self.assertEqual(merged[0]["bytes_down"], 123)
        self.assertEqual(merged[0]["bytes_up"], 456)

    def test_openwrt_firewall_setup_allows_only_lan_to_local_tun(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((list(args), dict(kwargs)))
            if list(args)[1:3] == ["-q", "get"]:
                return mock.Mock(returncode=1, stdout="", stderr="")
            if list(args)[1:] == ["export", "firewall"]:
                return mock.Mock(returncode=0, stdout="config defaults\n", stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(self.panel, "_openwrt_firewall_tools", return_value=("/sbin/uci", "/etc/init.d/firewall")):
            with mock.patch.object(self.panel.subprocess, "run", side_effect=fake_run):
                changed = self.panel._ensure_openwrt_local_tun_firewall("taml0")

        self.assertTrue(changed)
        commands = [call[0] for call in calls]
        self.assertIn(["/sbin/uci", "add_list", "firewall.tamizdat.device=taml0"], commands)
        self.assertIn(["/sbin/uci", "set", "firewall.lan_to_tamizdat.src=lan"], commands)
        self.assertIn(["/sbin/uci", "set", "firewall.lan_to_tamizdat.dest=tamizdat"], commands)
        self.assertIn(["/etc/init.d/firewall", "reload"], commands)

    def test_openwrt_init_status_maps_running_to_active(self):
        result = mock.Mock(returncode=0, stdout="running\\n", stderr="")
        with mock.patch.object(self.panel, "_openwrt_service_script", return_value="/etc/init.d/tamizdat-server"):
            with mock.patch.object(self.panel.subprocess, "run", return_value=result) as run:
                status, detail = self.panel.managed_service_status()
        self.assertEqual(status, "active")
        self.assertEqual(detail, "")
        run.assert_called_once_with(
            ["/etc/init.d/tamizdat-server", "status"],
            capture_output=True,
            text=True,
            timeout=2,
        )

    def test_routing_form_does_not_expose_redundant_inbound_tag(self):
        self.assertNotIn('id="ruleInbound"', self.panel.PANEL_HTML)
        self.assertNotIn("match.inbound_tag", self.panel.PANEL_HTML)

if __name__ == "__main__":
    unittest.main()
