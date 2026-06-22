#!/usr/bin/env python3
"""Smoke-test the panel CRUD helpers around shortid simplification.

Exercises:
  - create_user defaults pool_size to one H2 transport per user
  - rotate_user_epoch only changes master_shortid; epoch_key untouched
  - schema migration v2 → v3 leaves epoch_key column nullable

Runs against an isolated temp SQLite DB using TAMIZDAT_PANEL_DB_PATH
to avoid polluting the operator's panel.db.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_PY = os.path.join(HERE, "tamizdat-panel.py")


class PanelShortidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="tamizdat-panel-test-")
        cls.db_path = os.path.join(cls.tmpdir, "panel.db")
        os.environ["TAMIZDAT_PANEL_DB"] = cls.db_path
        os.environ["TAMIZDAT_PANEL_LEGACY_SHORTID"] = "/nonexistent"
        os.environ.setdefault("TAMIZDAT_SERVER_PID_PATH", "/nonexistent")
        cls.panel = SourceFileLoader("tamizdat_panel", PANEL_PY).load_module()
        cls.panel.ensure_db()

    def setUp(self):
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM users")

    def test_add_user_omits_epoch_key(self):
        u = self.panel.create_user({"name": "alice", "outbound_tag": "direct"})
        self.assertEqual(u["name"], "alice")
        with self.panel.db_conn() as con:
            row = con.execute(
                "SELECT epoch_key, pool_size, master_shortid FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        self.assertIsNone(row["epoch_key"], "epoch_key should be NULL after create_user")
        self.assertEqual(row["pool_size"], 1, "pool_size should default to 1 H2 transport")
        self.assertEqual(len(row["master_shortid"]), 16)

    def test_add_user_uses_server_default_pool_size(self):
        u"""Server-side default must control new users when the panel body
        omits pool_size."""
        prev_default = None
        with self.panel.db_conn() as con:
            prev_default = con.execute(
                "SELECT value FROM settings WHERE key='pool_size_default'"
            ).fetchone()
            con.execute("UPDATE settings SET value='3' WHERE key='pool_size_default'")
        try:
            u = self.panel.create_user({"name": "alice-3", "outbound_tag": "direct"})
            self.assertEqual(u["pool_size"], 3)
        finally:
            with self.panel.db_conn() as con:
                if prev_default:
                    con.execute(
                        "UPDATE settings SET value=? WHERE key='pool_size_default'",
                        (prev_default["value"],),
                    )

    def test_rotate_user_epoch_only_changes_shortid(self):
        u = self.panel.create_user({"name": "bob", "outbound_tag": "direct"})
        with self.panel.db_conn() as con:
            before = con.execute(
                "SELECT master_shortid, epoch_key FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        new_master = self.panel.rotate_user_epoch(u["id"])
        with self.panel.db_conn() as con:
            after = con.execute(
                "SELECT master_shortid, epoch_key FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        self.assertEqual(new_master, after["master_shortid"])
        self.assertNotEqual(before["master_shortid"], after["master_shortid"],
                            "rotate must change master_shortid")
        # Finding 1: epoch_key MUST NOT be written by rotate (post-pool drop).
        self.assertEqual(before["epoch_key"], after["epoch_key"],
                         "rotate must not write epoch_key")

    def test_schema_v3_epoch_key_nullable(self):
        with self.panel.db_conn() as con:
            cols = con.execute("PRAGMA table_info(users)").fetchall()
        col_map = {c["name"]: c for c in cols}
        self.assertIn("epoch_key", col_map)
        self.assertEqual(col_map["epoch_key"]["notnull"], 0,
                         "epoch_key must be nullable in v3 schema")
        self.assertIn("notification_pending", col_map,
                      "schema v3 must add notification_pending column")

    def test_user_row_dict_omits_master_shortid(self):
        """I-2: list/get-user response payload no longer surfaces shortid."""
        u = self.panel.create_user({"name": "carol", "outbound_tag": "direct"})
        self.assertNotIn("master_shortid", u,
                         "I-2: master_shortid must NOT appear in /api/users dict")
        self.assertIn("pool_size", u,
                      "pool_size should now surface as the user's H2 transport count")
        self.assertEqual(u["pool_size"], 1)

    def test_user_row_dict_includes_notification_pending(self):
        """I-4: notification_pending boolean must surface for the panel UI."""
        u = self.panel.create_user({"name": "dave", "outbound_tag": "direct"})
        self.assertIn("notification_pending", u)
        self.assertFalse(u["notification_pending"])

    def test_make_user_uri_loads_shortid_via_helper(self):
        """I-3: make_user_uri must work even though the user dict has no
        master_shortid field (helper fetches from DB by ID)."""
        u = self.panel.create_user({"name": "erin", "outbound_tag": "direct"})
        prev_pub = self.panel.server_pubkey_from_settings
        try:
            self.panel.server_pubkey_from_settings = lambda: ""
            self.assertIsNone(self.panel.make_user_uri(u))
        finally:
            self.panel.server_pubkey_from_settings = prev_pub
        # _get_user_shortid must still find the shortid in the DB.
        self.assertEqual(len(self.panel._get_user_shortid(u["id"])), 16)
        self.assertIsNone(self.panel._get_user_shortid("nonexistent-uid"))

    def test_schema_v4_quota_baseline_column(self):
        """quota-reset-split: v4 schema must surface the quota_baseline
        column (defaulting to 0) and _user_row_to_dict must propagate it
        to the JSON payload so the JS quotaBar can subtract."""
        with self.panel.db_conn() as con:
            cols = {c["name"]: c for c in con.execute("PRAGMA table_info(users)").fetchall()}
        self.assertIn("quota_baseline", cols, "v4 schema must add quota_baseline column")
        self.assertEqual(cols["quota_baseline"]["dflt_value"], "0",
                         "quota_baseline default must be 0")
        u = self.panel.create_user({"name": "frank", "outbound_tag": "direct"})
        self.assertIn("quota_baseline", u,
                      "/api/users dict must include quota_baseline for the JS quotaBar")
        self.assertEqual(u["quota_baseline"], 0)

    def test_pool_size_defaults_to_one_and_builds_exact_uri(self):
        """pool_size becomes the exact H2 transport count and must flow
        into make_user_uri as min=max transport bounds."""
        u = self.panel.create_user({"name": "greg", "outbound_tag": "direct"})
        self.assertEqual(u["pool_size"], 1)
        prev_pub = self.panel.server_pubkey_from_settings
        prev_short = self.panel._get_user_shortid
        prev_settings = self.panel.get_inbound_settings
        try:
            self.panel.server_pubkey_from_settings = lambda: "11" * 32
            self.panel._get_user_shortid = lambda _uid: "22" * 8
            self.panel.get_inbound_settings = lambda: {
                "inbound_masquerade_domain": "cover.example.com",
                "inbound_fingerprint": "mix",
                "inbound_bootstrap_sni": "",
                "inbound_public_port": 443,
                "inbound_listen_port": 7780,
            }
            uri = self.panel.make_user_uri(u)
        finally:
            self.panel.server_pubkey_from_settings = prev_pub
            self.panel._get_user_shortid = prev_short
            self.panel.get_inbound_settings = prev_settings
        self.assertIn("min_transports=1", uri)
        self.assertIn("max_transports=1", uri)

    def test_make_user_uri_uses_panel_hostname_setting(self):
        """Fresh installs may persist Public hostname only in settings.

        The user URI generator must honor settings.panel_hostname, not the
        module-load SERVER_HOST fallback ("example.com" when env is absent).
        """
        u = self.panel.create_user({"name": "api-host-user", "outbound_tag": "direct"})
        with self.panel.db_conn() as con:
            con.execute(
                "INSERT INTO settings(key,value) VALUES('panel_hostname','server.example.com') "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
            )

        prev_pub = self.panel.server_pubkey_from_settings
        prev_short = self.panel._get_user_shortid
        prev_settings = self.panel.get_inbound_settings
        prev_host = self.panel.SERVER_HOST
        try:
            setattr(self.panel, "SERVER_HOST", "example.com")
            setattr(self.panel, "server_pubkey_from_settings", lambda: "11" * 32)
            setattr(self.panel, "_get_user_shortid", lambda _uid: "22" * 8)
            setattr(self.panel, "get_inbound_settings", lambda: {
                "inbound_masquerade_domain": "cover.example.com",
                "inbound_fingerprint": "mix",
                "inbound_bootstrap_sni": "",
                "inbound_public_port": 443,
                "inbound_listen_port": 7780,
            })
            uri = self.panel.make_user_uri(u)
        finally:
            setattr(self.panel, "server_pubkey_from_settings", prev_pub)
            setattr(self.panel, "_get_user_shortid", prev_short)
            setattr(self.panel, "get_inbound_settings", prev_settings)
            setattr(self.panel, "SERVER_HOST", prev_host)

        self.assertTrue(uri.startswith("tamizdat://server.example.com:443/"), uri)
        self.assertNotIn("tamizdat://example.com", uri)

    def test_reset_user_quota_preserves_traffic_counters(self):
        """quota-reset-split A: reset_user_quota stamps quota_baseline =
        bytes_up+bytes_down + bumps bytes_reset_at + clears
        notification_pending, but LEAVES bytes_up/bytes_down untouched."""
        u = self.panel.create_user({"name": "gina", "outbound_tag": "direct"})
        with self.panel.db_conn() as con:
            con.execute(
                "UPDATE users SET bandwidth_cap=?, bytes_up=?, bytes_down=?, notification_pending=1 WHERE id=?",
                (1024 * 1024 * 1024, 700 * 1024 * 1024, 500 * 1024 * 1024, u["id"]),
            )
        self.panel.reset_user_quota(u["id"])
        with self.panel.db_conn() as con:
            row = con.execute(
                "SELECT bytes_up, bytes_down, quota_baseline, notification_pending FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        self.assertEqual(row["bytes_up"], 700 * 1024 * 1024,
                         "reset_user_quota must NOT zero bytes_up")
        self.assertEqual(row["bytes_down"], 500 * 1024 * 1024,
                         "reset_user_quota must NOT zero bytes_down")
        self.assertEqual(row["quota_baseline"], 1200 * 1024 * 1024,
                         "reset_user_quota must stamp baseline = bytes_up+bytes_down")
        self.assertEqual(row["notification_pending"], 0)

    def test_reset_user_bytes_zeros_everything(self):
        """quota-reset-split B: reset_user_bytes (the 🔄 hard-zero icon)
        wipes bytes_up + bytes_down + quota_baseline + clears
        notification_pending."""
        u = self.panel.create_user({"name": "hank", "outbound_tag": "direct"})
        with self.panel.db_conn() as con:
            con.execute(
                "UPDATE users SET bytes_up=?, bytes_down=?, quota_baseline=?, notification_pending=1 WHERE id=?",
                (123, 456, 789, u["id"]),
            )
        self.panel.reset_user_bytes(u["id"])
        with self.panel.db_conn() as con:
            row = con.execute(
                "SELECT bytes_up, bytes_down, quota_baseline, notification_pending FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        self.assertEqual(row["bytes_up"], 0)
        self.assertEqual(row["bytes_down"], 0)
        self.assertEqual(row["quota_baseline"], 0)
        self.assertEqual(row["notification_pending"], 0)

    def test_schema_v5_notification_text_column(self):
        """Phase C: v5 schema must surface the notification_text column
        (nullable, default NULL) and _user_row_to_dict must propagate it
        to the JSON payload so the JS edit-user modal can render it."""
        with self.panel.db_conn() as con:
            cols = {c["name"]: c for c in con.execute("PRAGMA table_info(users)").fetchall()}
        self.assertIn("notification_text", cols, "v5 schema must add notification_text column")
        u = self.panel.create_user({"name": "iris", "outbound_tag": "direct"})
        self.assertIn("notification_text", u,
                      "/api/users dict must include notification_text for the JS edit-user modal")
        self.assertEqual(u["notification_text"], "")

    def test_schema_v6_h2_peak_columns(self):
        """H2 diagnostics: per-user peak counters must be present in schema
        and propagated to /api/users payload."""
        with self.panel.db_conn() as con:
            cols = {c["name"]: c for c in con.execute("PRAGMA table_info(users)").fetchall()}
        for name in ("h2_peak_streams", "h2_peak_tcp_streams", "h2_peak_udp_streams", "h2_peak_at"):
            self.assertIn(name, cols, f"schema must add {name}")
            self.assertEqual(cols[name]["dflt_value"], "0")
        u = self.panel.create_user({"name": "h2-user", "outbound_tag": "direct"})
        with self.panel.db_conn() as con:
            con.execute(
                "UPDATE users SET h2_peak_streams=201, h2_peak_tcp_streams=200, h2_peak_udp_streams=3, h2_peak_at=12345 WHERE id=?",
                (u["id"],),
            )
        u = self.panel.get_user(u["id"])
        self.assertEqual(u["h2_peak_streams"], 201)
        self.assertEqual(u["h2_peak_tcp_streams"], 200)
        self.assertEqual(u["h2_peak_udp_streams"], 3)
        self.assertEqual(u["h2_peak_at"], 12345)
        self.assertEqual(u["h2_live_streams"], 0)
        self.assertEqual(u["h2_live_tcp_streams"], 0)
        self.assertEqual(u["h2_live_udp_streams"], 0)

    def test_merge_live_h2_counts(self):
        users = [{"id": "u1", "h2_live_streams": 0, "h2_live_tcp_streams": 0, "h2_live_udp_streams": 0}]
        self.panel._merge_live_user_counts(users, {
            "u1": {
                "h2_live_streams": 7,
                "h2_live_tcp_streams": 5,
                "h2_live_udp_streams": 2,
            }
        })
        self.assertEqual(users[0]["h2_live_streams"], 7)
        self.assertEqual(users[0]["h2_live_tcp_streams"], 5)
        self.assertEqual(users[0]["h2_live_udp_streams"], 2)

    def test_update_user_notification_text_roundtrip(self):
        """Phase C: update_user accepts notification_text in the PUT body,
        flips notification_pending=1 on non-empty value, and clears both
        on empty value."""
        u = self.panel.create_user({"name": "jack", "outbound_tag": "direct"})
        # Set a manual notification.
        u2 = self.panel.update_user(u["id"], {"notification_text": "Quota top-up needed"})
        self.assertEqual(u2["notification_text"], "Quota top-up needed")
        self.assertTrue(u2["notification_pending"])
        # Clear it.
        u3 = self.panel.update_user(u["id"], {"notification_text": ""})
        self.assertEqual(u3["notification_text"], "")
        self.assertFalse(u3["notification_pending"])
        # 512-byte cap.
        with self.assertRaises(ValueError):
            self.panel.update_user(u["id"], {"notification_text": "x" * 513})

    def test_broadcast_notification_writes_to_all_users(self):
        """Phase C broadcast: setting a system-wide notification stamps
        EVERY user's notification_text with a "BROADCAST: " prefix and
        flips notification_pending=1 across the board."""
        a = self.panel.create_user({"name": "kara", "outbound_tag": "direct"})
        b = self.panel.create_user({"name": "leon", "outbound_tag": "direct"})
        self.panel.broadcast_notification("Servicing tomorrow")
        with self.panel.db_conn() as con:
            rows = {r["id"]: r for r in con.execute(
                "SELECT id, notification_text, notification_pending FROM users").fetchall()}
        for uid in (a["id"], b["id"]):
            self.assertEqual(rows[uid]["notification_text"], "BROADCAST: Servicing tomorrow")
            self.assertEqual(rows[uid]["notification_pending"], 1)
        # Empty text clears every row's queue.
        self.panel.broadcast_notification("")
        with self.panel.db_conn() as con:
            rows = {r["id"]: r for r in con.execute(
                "SELECT id, notification_text, notification_pending FROM users").fetchall()}
        for uid in (a["id"], b["id"]):
            self.assertIsNone(rows[uid]["notification_text"])
            self.assertEqual(rows[uid]["notification_pending"], 0)
        with self.assertRaises(ValueError):
            self.panel.broadcast_notification("x" * 513)

    def test_reset_user_quota_clears_notification_text(self):
        """Phase C: reset_user_quota clears notification_text along with
        notification_pending so the operator can free a user from a
        stuck-notification state in one click."""
        u = self.panel.create_user({"name": "milo", "outbound_tag": "direct"})
        self.panel.update_user(u["id"], {"notification_text": "stuck message"})
        self.panel.reset_user_quota(u["id"])
        with self.panel.db_conn() as con:
            row = con.execute(
                "SELECT notification_text, notification_pending FROM users WHERE id=?",
                (u["id"],),
            ).fetchone()
        self.assertIsNone(row["notification_text"])
        self.assertEqual(row["notification_pending"], 0)


class RoutingLayoutTests(unittest.TestCase):
    """Sortable.js (2026-05-10): test the new atomic set_routing_layout
    helper that backs POST /api/routing/layout.

    Lives in its own TestCase so the shared tmp DB / panel module loaded
    by PanelShortidTests is reused via the class-level fixture.
    """
    @classmethod
    def setUpClass(cls):
        cls.panel = PanelShortidTests.panel
        cls.panel.ensure_db()

    def setUp(self):
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM routing_rules")
            con.execute("DELETE FROM routing_folders")
            # Ensure 'direct' outbound row exists so _routing_validate_outbound
            # accepts our test rules without scaffolding the whole outbounds
            # table from real network config.
            con.execute(
                "INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) "
                "VALUES('direct','direct',NULL,NULL,?,?)",
                (1, 1),
            )

    def _mk_rule(self, desc):
        r = self.panel.create_routing_rule({
            "outbound_tag": "direct",
            "description_override": desc,
            "match": {"domain": [f"example-{desc}.test"]},
        })
        return r["id"]

    def _mk_folder(self, name):
        f = self.panel.create_routing_folder({"name": name})
        return f["id"]

    def test_set_routing_layout_atomic_reassigns_priorities(self):
        """Spec example: 2 folders + 4 rules, payload
        [F1(children=[R3,R1]), R2, F2(children=[]), R4]
        ⇒ F1.pri=1, R3.folder=F1 R3.pri=1, R1.folder=F1 R1.pri=2,
        R2.folder=NULL R2.pri=2, F2.pri=3, R4.folder=NULL R4.pri=4."""
        f1 = self._mk_folder("F1")
        f2 = self._mk_folder("F2")
        r1 = self._mk_rule("R1")
        r2 = self._mk_rule("R2")
        r3 = self._mk_rule("R3")
        r4 = self._mk_rule("R4")
        out = self.panel.set_routing_layout([
            {"kind": "folder", "id": f1, "children": [r3, r1]},
            {"kind": "rule", "id": r2},
            {"kind": "folder", "id": f2, "children": []},
            {"kind": "rule", "id": r4},
        ])
        self.assertTrue(out["ok"])
        self.assertEqual(len(out["rules"]), 4)
        self.assertEqual(len(out["folders"]), 2)
        # Read raw to bypass any list-ordering surprises.
        with self.panel.db_conn() as con:
            folders = {r["id"]: r for r in con.execute(
                "SELECT id, priority FROM routing_folders").fetchall()}
            rules = {r["id"]: r for r in con.execute(
                "SELECT id, priority, folder_id FROM routing_rules").fetchall()}
        self.assertEqual(folders[f1]["priority"], 1)
        self.assertEqual(folders[f2]["priority"], 3)
        self.assertEqual(rules[r3]["folder_id"], f1)
        self.assertEqual(rules[r3]["priority"], 1)
        self.assertEqual(rules[r1]["folder_id"], f1)
        self.assertEqual(rules[r1]["priority"], 2)
        self.assertIsNone(rules[r2]["folder_id"])
        self.assertEqual(rules[r2]["priority"], 2)
        self.assertIsNone(rules[r4]["folder_id"])
        self.assertEqual(rules[r4]["priority"], 4)

    def test_set_routing_layout_rejects_unknown_id(self):
        """Unknown folder id triggers ValueError before any DB write."""
        f1 = self._mk_folder("F1")
        r1 = self._mk_rule("R1")
        with self.assertRaises(ValueError):
            self.panel.set_routing_layout([
                {"kind": "folder", "id": f1, "children": [r1]},
                {"kind": "folder", "id": 999999, "children": []},
            ])
        # Side-effect free: priorities preserved from create_routing_*
        with self.panel.db_conn() as con:
            f1_pri = con.execute(
                "SELECT priority FROM routing_folders WHERE id=?", (f1,)
            ).fetchone()["priority"]
        self.assertGreater(f1_pri, 0,
                           "rollback contract: folder priority must remain positive")

    def test_set_routing_layout_rejects_duplicate_id(self):
        """A rule appearing in both a folder body and at the top level
        must be rejected — likewise a folder repeated twice."""
        f1 = self._mk_folder("F1")
        r1 = self._mk_rule("R1")
        with self.assertRaises(ValueError):
            self.panel.set_routing_layout([
                {"kind": "folder", "id": f1, "children": [r1]},
                {"kind": "rule", "id": r1},   # duplicate
            ])
        f2 = self._mk_folder("F2")
        with self.assertRaises(ValueError):
            self.panel.set_routing_layout([
                {"kind": "folder", "id": f1, "children": []},
                {"kind": "folder", "id": f1, "children": []},   # duplicate
                {"kind": "folder", "id": f2, "children": []},
            ])

    def test_set_routing_layout_handles_empty_folder(self):
        """Empty children array is OK — folder still gets a priority slot."""
        f1 = self._mk_folder("F1")
        r1 = self._mk_rule("R1")
        out = self.panel.set_routing_layout([
            {"kind": "folder", "id": f1, "children": []},
            {"kind": "rule", "id": r1},
        ])
        self.assertTrue(out["ok"])
        with self.panel.db_conn() as con:
            f1_pri = con.execute(
                "SELECT priority FROM routing_folders WHERE id=?", (f1,)
            ).fetchone()["priority"]
            r1_row = con.execute(
                "SELECT priority, folder_id FROM routing_rules WHERE id=?", (r1,)
            ).fetchone()
        self.assertEqual(f1_pri, 1)
        self.assertEqual(r1_row["priority"], 2)
        self.assertIsNone(r1_row["folder_id"],
                          "rule listed outside any folder must have folder_id=NULL")


class SettingsRefactorPhase2Tests(unittest.TestCase):
    """Settings refactor Phase 2 (2026-05-11) — flat blocks, real GET/PUT,
    panel-self-config. Covers:
      - put_panel_settings writes panel_* keys + reports restart_required
      - get_inbound_settings + the new GET /api/tamizdat response shape
        respond to flat-table edits
      - PUT /api/tamizdat (through put_inbound_settings) persists to flat keys
      - panel_hostname env fallback when DB key is empty
      - legacy panel_inbounds_json one-shot migration is idempotent and
        only fires once per DB
    """
    @classmethod
    def setUpClass(cls):
        cls.panel = PanelShortidTests.panel
        cls.panel.ensure_db()

    def setUp(self):
        # Drop every settings row we want to mutate so each test starts
        # from a known state. ensure_db re-installs DEFAULT_SETTINGS via
        # INSERT OR IGNORE on the next call (which the panel triggers
        # automatically through get_inbound_settings).
        keys = (
            "panel_hostname", "panel_port", "panel_base_path",
            "panel_tls_cert_path", "panel_tls_key_path",
            "inbound_listen_port", "inbound_listen_addr",
            "inbound_fallback_server", "inbound_fallback_port",
            "pool_size_default",
            "inbound_bundle_enabled",
        )
        with self.panel.db_conn() as con:
            for k in keys:
                con.execute("DELETE FROM settings WHERE key=?", (k,))
            con.execute(
                "DELETE FROM schema_meta WHERE key='legacy_inbounds_migrated_to_flat'"
            )
        # Re-prime defaults.
        self.panel.ensure_db()

    def test_put_panel_settings_writes_db_keys(self):
        """put_panel_settings writes hostname/port/base_path/TLS to flat
        settings rows. All five keys end up persisted."""
        out = self.panel.put_panel_settings({
            "panel_hostname":       "example.com",
            "panel_port":           "9999",
            "panel_base_path":      "/abyss-aaaa",
            "panel_tls_cert_path":  "/etc/cert.pem",
            "panel_tls_key_path":   "/etc/key.pem",
        })
        self.assertTrue(out["restart_required"],
                        "port + base_path + TLS-paths all flag restart")
        self.assertGreaterEqual(len(out["changed"]), 5)
        with self.panel.db_conn() as con:
            got = {
                r["key"]: r["value"]
                for r in con.execute(
                    "SELECT key, value FROM settings WHERE key IN "
                    "('panel_hostname','panel_port','panel_base_path',"
                    " 'panel_tls_cert_path','panel_tls_key_path')").fetchall()
            }
        self.assertEqual(got["panel_hostname"],      "example.com")
        self.assertEqual(got["panel_port"],          "9999")
        self.assertEqual(got["panel_base_path"],     "/abyss-aaaa")
        self.assertEqual(got["panel_tls_cert_path"], "/etc/cert.pem")
        self.assertEqual(got["panel_tls_key_path"],  "/etc/key.pem")

    def test_put_panel_settings_restart_required_flags(self):
        """Only port / base_path / TLS-paths flag restart_required.
        hostname-only change does NOT (panel reads it fresh on URI build)."""
        # First wipe out any defaults that might collide:
        self.panel.put_panel_settings({"panel_hostname": "", "panel_port": "8888",
                                       "panel_base_path": "", "panel_tls_cert_path": "",
                                       "panel_tls_key_path": ""})
        # hostname-only → no restart.
        out = self.panel.put_panel_settings({"panel_hostname": "new.example"})
        self.assertFalse(out["restart_required"],
                         "hostname-only change must not flag restart")
        self.assertEqual(out["changed"], ["panel_hostname"])
        # port-only → restart.
        out2 = self.panel.put_panel_settings({"panel_port": "7777"})
        self.assertTrue(out2["restart_required"])
        # base_path-only → restart.
        out3 = self.panel.put_panel_settings({"panel_base_path": "/abc"})
        self.assertTrue(out3["restart_required"])
        # TLS cert-only — also requires restart, but bare cert without key
        # is rejected (both-or-neither contract).
        with self.assertRaises(ValueError):
            self.panel.put_panel_settings({"panel_tls_cert_path": "/x.pem"})

    def test_tamizdat_restart_required_flags(self):
        """Settings that are read once at tamizdat-server boot must surface
        restart_required. Live/SIGHUP-safe or URI-hint fields must not."""
        restart_keys = [
            "inbound_listen_port",
            "inbound_listen_addr",
            "inbound_cert_path",
            "inbound_key_path",
            "inbound_priv_key",
            "inbound_masquerade_domain",
            "inbound_masquerade_pool",
            "inbound_proxy_protocol",
            "inbound_proxy_protocol_from",
            "inbound_max_streams",
            "inbound_pool_variant",
            "inbound_sniff_enabled",
        ]
        for key in restart_keys:
            with self.subTest(key=key):
                self.assertTrue(self.panel.tamizdat_restart_required([key]))

        live_keys = [
            "inbound_public_port",
            "inbound_jitter_ms",
            "inbound_fingerprint",
            "inbound_bootstrap_sni",
            "inbound_geoip_url",
            "inbound_geosite_url",
            "panel_test_target",
        ]
        for key in live_keys:
            with self.subTest(key=key):
                self.assertFalse(self.panel.tamizdat_restart_required([key]))

    def test_put_panel_settings_rejects_bad_port(self):
        """Out-of-range or non-integer port raises ValueError before any
        row is written."""
        with self.assertRaises(ValueError):
            self.panel.put_panel_settings({"panel_port": "0"})
        with self.assertRaises(ValueError):
            self.panel.put_panel_settings({"panel_port": "70000"})
        with self.assertRaises(ValueError):
            self.panel.put_panel_settings({"panel_port": "notanumber"})

    def test_upsert_balancer_persists_config_and_load_config_surfaces_members(self):
        """Balancer outbounds use kind=balancer and store their mode/member
        list as JSON in outbounds.uri so the Go registry and panel API see
        the same config."""
        self.panel.upsert_outbound({
            "tag": "bal-panel",
            "kind": "balancer",
            "mode": "rr",
            "members": ["direct", "block"],
            "note": "panel test",
        })
        try:
            with self.panel.db_conn() as con:
                row = con.execute("SELECT kind, uri, note FROM outbounds WHERE tag='bal-panel'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["kind"], "balancer")
            payload = json.loads(row["uri"])
            self.assertEqual(payload["mode"], "round_robin")
            self.assertEqual(payload["outbounds"], ["direct", "block"])
            self.assertEqual(row["note"], "panel test")

            cfg = self.panel.load_config()
            ob = next(o for o in cfg["outbounds"] if o["tag"] == "bal-panel")
            self.assertEqual(ob["type"], "balancer")
            self.assertEqual(ob["mode"], "round_robin")
            self.assertEqual(ob["outbounds"], ["direct", "block"])
            self.assertTrue(ob["uri"].startswith("{"))
        finally:
            with self.panel.db_conn() as con:
                con.execute("DELETE FROM outbounds WHERE tag='bal-panel'")

    def test_outbound_api_entry_surfaces_balancer_high_rtt_fields(self):
        """GET /api/outbounds must preserve parsed high-RTT balancer fields.

        Regression: load_config() parsed failover_on_high_rtt/rtt_threshold_ms
        from outbounds.uri, but the route-specific JSON projection dropped
        them, so reopening the Edit balancer modal looked like the 200ms value
        had not been saved even though the DB row was correct.
        """
        self.panel.upsert_outbound({
            "tag": "bal-rtt-panel",
            "kind": "balancer",
            "mode": "alive",
            "members": ["direct", "block"],
            "failover_on_high_rtt": True,
            "rtt_threshold_ms": 200,
        })
        try:
            cfg = self.panel.load_config()
            ob = next(o for o in cfg["outbounds"] if o["tag"] == "bal-rtt-panel")
            entry = self.panel.outbound_api_entry(ob, user_count=0)
            self.assertTrue(entry["failover_on_high_rtt"])
            self.assertEqual(entry["rtt_threshold_ms"], 200)
            self.assertEqual(entry["mode"], "alive")
            self.assertEqual(entry["outbounds"], ["direct", "block"])
            self.assertEqual(json.loads(entry["uri"])["rtt_threshold_ms"], 200)
        finally:
            with self.panel.db_conn() as con:
                con.execute("DELETE FROM outbounds WHERE tag='bal-rtt-panel'")

    def test_upsert_balancer_rejects_empty_members(self):
        with self.assertRaises(ValueError):
            self.panel.upsert_outbound({"tag": "bal-empty", "kind": "balancer", "mode": "alive", "outbounds": []})

    def test_get_tamizdat_reads_flat_settings(self):
        """The new GET /api/tamizdat reads flat inbound_* rows directly
        (no longer via load_config's legacy panel_inbounds_json). Writing
        inbound_listen_port=881 through put_inbound_settings must surface
        on the next get_inbound_settings call as listen_port=881."""
        self.panel.put_inbound_settings({
            "inbound_listen_port":   "881",
            "inbound_listen_addr":   "0.0.0.0",
            "inbound_fallback_server": "127.0.0.1",
            "inbound_fallback_port": "8080",
            "pool_size_default":     "2",
            "inbound_bundle_enabled": "0",
        })
        s = self.panel.get_inbound_settings()
        self.assertEqual(s["inbound_listen_port"],     "881")
        self.assertEqual(s["inbound_listen_addr"],     "0.0.0.0")
        self.assertEqual(s["inbound_fallback_server"], "127.0.0.1")
        self.assertEqual(s["inbound_fallback_port"],   "8080")
        self.assertEqual(s["pool_size_default"],       "2")
        self.assertEqual(s["inbound_bundle_enabled"],  "0")

    def test_put_tamizdat_persists_via_inbound(self):
        """End-to-end body→flat-keys path that PUT /api/tamizdat uses:
        the operator types listen_port:881 in the form, the JS body shape
        ({listen_port:881, …}) is mapped to flat keys, and put_inbound_settings
        writes inbound_listen_port=881."""
        # Use enabled=False to ensure a write happens (default is "1").
        body = {
            "enabled":      False,   # → inbound_bundle_enabled "0"
            "listen_port":  881,     # → inbound_listen_port    "881"
            "public_port":  443,
            "fingerprint":  "chrome",
            "fallback_port": 9000,
            "pool_size_default": 2,
        }
        # Mimic the GET-handler's mapping inline (same dict as the route).
        flat_map = {
            "enabled": "inbound_bundle_enabled",
            "listen_port": "inbound_listen_port",
            "public_port": "inbound_public_port",
            "fingerprint": "inbound_fingerprint",
            "fallback_port": "inbound_fallback_port",
            "pool_size_default": "pool_size_default",
        }
        flat = {flat_map[k]: v for k, v in body.items()}
        changed = self.panel.put_inbound_settings(flat)
        self.assertIn("inbound_listen_port", changed)
        self.assertIn("inbound_bundle_enabled", changed,
                      "enabled=False must overwrite the install-time default of 1")
        self.assertIn("pool_size_default", changed)
        with self.panel.db_conn() as con:
            row_port = con.execute(
                "SELECT value FROM settings WHERE key='inbound_listen_port'"
            ).fetchone()
            row_enabled = con.execute(
                "SELECT value FROM settings WHERE key='inbound_bundle_enabled'"
            ).fetchone()
            row_fp = con.execute(
                "SELECT value FROM settings WHERE key='inbound_fingerprint'"
            ).fetchone()
            row_pool = con.execute(
                "SELECT value FROM settings WHERE key='pool_size_default'"
            ).fetchone()
        self.assertEqual(row_port["value"], "881")
        self.assertEqual(row_enabled["value"], "0")
        self.assertEqual(row_fp["value"], "chrome")
        self.assertEqual(row_pool["value"], "2")

    def test_put_tamizdat_rejects_bad_fingerprint(self):
        """Validation: unknown fingerprint value rejected with ValueError."""
        with self.assertRaises(ValueError):
            self.panel.put_inbound_settings({"inbound_fingerprint": "edge"})

    def test_put_tamizdat_rejects_bad_priv_key(self):
        """Validation: priv key must be 64 lowercase hex chars or empty."""
        with self.assertRaises(ValueError):
            self.panel.put_inbound_settings({"inbound_priv_key": "xxx"})
        # 64-hex passes
        self.panel.put_inbound_settings({"inbound_priv_key": "a" * 64})

    def test_panel_settings_env_fallback(self):
        """_panel_setting_with_env_fallback: empty DB value → env var → default."""
        # Wipe row to simulate empty.
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM settings WHERE key='panel_hostname'")
            con.execute(
                "INSERT INTO settings(key,value) VALUES('panel_hostname','')"
            )
        os.environ["TAMIZDAT_PANEL_SERVER_HOST"] = "fallback.example.com"
        try:
            got = self.panel._panel_setting_with_env_fallback(
                "panel_hostname", "TAMIZDAT_PANEL_SERVER_HOST", "default.example.com"
            )
            self.assertEqual(got, "fallback.example.com")
        finally:
            del os.environ["TAMIZDAT_PANEL_SERVER_HOST"]
        # With env removed, the hard default takes over.
        got2 = self.panel._panel_setting_with_env_fallback(
            "panel_hostname", "TAMIZDAT_PANEL_SERVER_HOST", "default.example.com"
        )
        self.assertEqual(got2, "default.example.com")
        # When DB has a value, env is ignored.
        with self.panel.db_conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('panel_hostname','db.example.com')"
            )
        got3 = self.panel._panel_setting_with_env_fallback(
            "panel_hostname", "TAMIZDAT_PANEL_SERVER_HOST", "default.example.com"
        )
        self.assertEqual(got3, "db.example.com")

    def test_make_master_uri_uses_panel_hostname_env_fallback(self):
        """Master URI should use the same DB→env→default hostname chain as user URIs."""
        with self.panel.db_conn() as con:
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('panel_hostname','')")
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('inbound_priv_key',?)", ("a" * 64,))
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('inbound_public_port','443')")
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('inbound_masquerade_domain','cover.example.com')")
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('inbound_fingerprint','mix')")
        prev_host = self.panel.SERVER_HOST
        os.environ["TAMIZDAT_PANEL_SERVER_HOST"] = "env-host.example"
        try:
            setattr(self.panel, "SERVER_HOST", "example.com")
            uri = self.panel.make_master_uri_from_settings()
        finally:
            setattr(self.panel, "SERVER_HOST", prev_host)
            del os.environ["TAMIZDAT_PANEL_SERVER_HOST"]
        self.assertTrue(uri.startswith("tamizdat://env-host.example:443/"), uri)
        self.assertNotIn("tamizdat://example.com", uri)

    def test_legacy_tamizdat_generators_use_panel_hostname_setting(self):
        """Dead/legacy config generators must not reintroduce SERVER_HOST/example.com."""
        with self.panel.db_conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('panel_hostname','server.example.com')"
            )
        cfg = {"inbounds": [{
            "type": "tamizdat",
            "private_key": "b" * 64,
            "master_short_id": "22" * 8,
            "public_port": 443,
            "masquerade_domain": "cover.example.com",
            "fingerprint": "mix",
        }]}
        prev_host = self.panel.SERVER_HOST
        try:
            setattr(self.panel, "SERVER_HOST", "example.com")
            uri = self.panel.make_tamizdat_uri(cfg)
            js = self.panel.make_tamizdat_json(cfg)
        finally:
            setattr(self.panel, "SERVER_HOST", prev_host)
        self.assertTrue(uri.startswith("tamizdat://server.example.com:443/"), uri)
        self.assertEqual(js["server"], "server.example.com:443")

    def test_legacy_inbound_migration(self):
        """One-shot migration: pre-Phase-2 install has a populated
        panel_inbounds_json blob with type=tamizdat, listen_port=778. After
        ensure_db, the flat inbound_listen_port row must hold "778" — and a
        second ensure_db call must not re-run the migration (idempotent)."""
        import json
        prev_ensure = self.panel._ensure_db_done
        # Wipe the marker + flat keys, install a legacy JSON blob.
        with self.panel.db_conn() as con:
            con.execute(
                "DELETE FROM schema_meta WHERE key='legacy_inbounds_migrated_to_flat'"
            )
            con.execute("DELETE FROM settings WHERE key='inbound_listen_port'")
            con.execute("DELETE FROM settings WHERE key='inbound_public_port'")
            con.execute("DELETE FROM settings WHERE key='inbound_fallback_server'")
            legacy = [{
                "type": "tamizdat",
                "tag": "tamizdat-in",
                "listen_port": 778,
                "public_port": 443,
                "private_key": "b" * 64,
                "cert_path": "/legacy/cert.pem",
                "fallback": {"server": "127.0.0.1", "server_port": 8080},
                "masquerade_domain": "ok.ru",
            }]
            con.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('panel_inbounds_json', ?)",
                (json.dumps(legacy),),
            )
        try:
            # ensure_db caches one bootstrap pass per process, so the test
            # forces a re-run after staging the legacy rows.
            self.panel._ensure_db_done = False
            self.panel.ensure_db()
            with self.panel.db_conn() as con:
                port_row     = con.execute("SELECT value FROM settings WHERE key='inbound_listen_port'").fetchone()
                pub_row      = con.execute("SELECT value FROM settings WHERE key='inbound_public_port'").fetchone()
                cert_row     = con.execute("SELECT value FROM settings WHERE key='inbound_cert_path'").fetchone()
                fb_serv_row  = con.execute("SELECT value FROM settings WHERE key='inbound_fallback_server'").fetchone()
                fb_port_row  = con.execute("SELECT value FROM settings WHERE key='inbound_fallback_port'").fetchone()
                marker       = con.execute("SELECT 1 FROM schema_meta WHERE key='legacy_inbounds_migrated_to_flat'").fetchone()
            self.assertEqual(port_row["value"],    "778",
                             "migration must copy legacy listen_port into flat row")
            self.assertEqual(pub_row["value"],     "443")
            self.assertEqual(cert_row["value"],    "/legacy/cert.pem")
            self.assertEqual(fb_serv_row["value"], "127.0.0.1")
            self.assertEqual(fb_port_row["value"], "8080")
            self.assertIsNotNone(marker, "migration marker must be set")
            # Re-run ensure_db — marker prevents re-migration. Modify a flat
            # row to a custom operator value, call ensure_db, and verify the
            # custom value survives.
            with self.panel.db_conn() as con:
                con.execute(
                    "UPDATE settings SET value='9999' WHERE key='inbound_listen_port'"
                )
            self.panel._ensure_db_done = False
            self.panel.ensure_db()
            with self.panel.db_conn() as con:
                still = con.execute(
                    "SELECT value FROM settings WHERE key='inbound_listen_port'"
                ).fetchone()
            self.assertEqual(still["value"], "9999",
                             "idempotency: re-run must not overwrite operator edits")
        finally:
            with self.panel.db_conn() as con:
                con.execute("DELETE FROM settings WHERE key='panel_inbounds_json'")
            self.panel._ensure_db_done = prev_ensure or self.panel._ensure_db_done

    def test_make_master_uri_from_settings_empty_without_priv(self):
        """No priv key configured → empty URI (UI shows placeholder)."""
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM settings WHERE key='inbound_priv_key'")
            con.execute("DELETE FROM settings WHERE key='inbound_priv_key_path'")
        self.assertEqual(self.panel.make_master_uri_from_settings(), "")

    def test_make_master_uri_from_settings_with_priv(self):
        """Valid priv key → URI carries tamizdat:// + derived pubkey."""
        self.panel.put_inbound_settings({
            "inbound_priv_key":       "c" * 64,
            "inbound_listen_port":    "7780",
            "inbound_public_port":    "443",
            "inbound_masquerade_domain": "ok.ru",
        })
        uri = self.panel.make_master_uri_from_settings()
        self.assertTrue(uri.startswith("tamizdat://"))
        self.assertIn("pubkey=", uri)
        self.assertIn("shortid=0000000000000000", uri,
                      "master URI uses placeholder shortid (per-user URIs come from /api/users)")
        self.assertIn("sni=ok.ru", uri)


class SettingsMockupPortTests(unittest.TestCase):
    """Settings mockup port (2026-05-11) — verifies the designer-mockup
    integration into PANEL_HTML. Covers:
      - PANEL_HTML carries the new sub-rail + 8 group cards + save-bar
        markers (so a static grep sees the mockup landed)
      - dirty bar HTML structure is present (id="saveBar" + sb-changes
        + Discard/Save buttons)
      - the save handlers (settingsSaveAll / saveTamizdatServer /
        savePanel) and dirty-tracker (settingsMarkDirty /
        settingsClearDirty) are wired in JS
      - field IDs match the load/save handlers (regression guard against
        the IDs drifting between HTML and JS)
    """
    @classmethod
    def setUpClass(cls):
        cls.panel = PanelShortidTests.panel
        # PANEL_HTML is a module-level string in tamizdat-panel.py — pull it
        # directly off the module so we can assert against the rendered
        # mockup without booting the HTTP server.
        cls.html = cls.panel.PANEL_HTML

    def test_subrail_and_group_markers_present(self):
        """Every group ID + sub-rail nav item from the mockup is in HTML.

        2026-05-25 cleanup: g-net (Anti-DPI) and g-danger (Danger zone)
        groups were dropped along with the Pool variant / Per-user TCP-UDP
        stream fields. The User group (g-user) was added for the
        change-password form. Existing groups must still be present.
        """
        markers = [
            "sub-rail", "sub-rail-title",
            'id="g-server"', 'id="g-wgturn"', 'id="g-tls"', 'id="g-masq"',
            'id="g-routing"', 'id="g-panel"',
            'id="g-broadcast"', 'id="g-user"',
            "pill-live", "pill-restart", "pill-self", "pill-beta",
        ]
        missing = [m for m in markers if m not in self.html]
        self.assertEqual(missing, [], f"PANEL_HTML missing mockup markers: {missing}")
        # Removed groups must NOT come back without a deliberate test update.
        # The .danger-card CSS rule is left in stylesheet (orphan; harmless)
        # so we only assert on the structural section IDs here.
        for gone in ('id="g-net"', 'id="g-danger"', 'class="group danger-card"'):
            self.assertNotIn(gone, self.html,
                             f"removed marker {gone!r} resurfaced — check the cleanup")

    def test_save_bar_structure_present(self):
        """Sticky save bar HTML is rendered with Save+Discard buttons."""
        self.assertIn('id="saveBar"', self.html)
        self.assertIn('id="btnSave"', self.html)
        self.assertIn('id="btnDiscard"', self.html)
        self.assertIn('id="changeCount"', self.html)
        self.assertIn("Unsaved changes", self.html)
        self.assertIn("Save all", self.html)
        self.assertIn("Discard", self.html)

    def test_chip_and_line_list_widgets_present(self):
        """Chip pool for SNI rotation + line-lists for geo URLs are wired."""
        self.assertIn('id="sniChips"', self.html, "chip pool must be in HTML")
        self.assertIn('id="chipCount"', self.html)
        self.assertIn('id="geoipList"', self.html, "GeoIP line-list must be in HTML")
        self.assertIn('id="geositeList"', self.html, "Geosite line-list must be in HTML")
        # The hidden backing textareas still carry the IDs the existing
        # saveTamizdatServer / saveGeoUrl handlers expect.
        self.assertIn('id="tamMasqPool"', self.html)
        self.assertIn('id="setGeoipUrl"', self.html)
        self.assertIn('id="setGeositeUrl"', self.html)

    def test_segmented_controls_present(self):
        """bindSeg → tamListenAddr + utlsSeg → tamFp segmented controls."""
        self.assertIn('id="bindSeg"', self.html)
        self.assertIn('id="utlsSeg"', self.html)
        self.assertIn('data-val="127.0.0.1"', self.html)
        self.assertIn('data-val="0.0.0.0"', self.html)
        self.assertIn('data-val="custom"', self.html)
        self.assertIn('data-val="mix"', self.html)

    def test_js_handlers_wired(self):
        """Mockup JS interactions + dirty-tracker + save dispatcher are wired."""
        for fn in [
            "function initSettingsMockup",
            "function settingsMarkDirty",
            "function settingsClearDirty",
            "function snapshotSettingsBaseline",
            "function syncSettingsUIControls",
            "async function settingsSaveAll",
            "async function dangerResetCounters",
            "function chipsRender",
            "function lineListRender",
            "window.addGeoLine",
        ]:
            self.assertIn(fn, self.html, f"JS handler {fn!r} missing from PANEL_HTML")

    def test_save_all_reboot_dialog_wired(self):
        """Save all must offer an explicit Reboot action when saved settings
        require service restart; otherwise Settings becomes effectively
        read-only for startup-bound fields."""
        markers = [
            "Reboot required",
            "Reboot services",
            "Reboot server",
            "Reboot panel",
            "reboot deferred",
            "restart_required",
            "H+'/api/service'",
            "H+'/api/panel/restart'",
        ]
        missing = [m for m in markers if m not in self.html]
        self.assertEqual(missing, [], f"Save all reboot flow missing markers: {missing}")

    def test_field_ids_match_load_save_handlers(self):
        """Field IDs in the HTML match the IDs that loadSettings() reads and
        saveTamizdatServer()/savePanel() write — guards against the next
        refactor renaming an ID and silently breaking persistence."""
        ids_used_by_js = [
            # Tamizdat block — keys consumed by loadSettings + saveTamizdatServer.
            # 2026-05-11 dead-mine cleanup dropped: tamEnabled (no Go reader for
            # inbound_bundle_enabled), tamFallServ/tamFallPort (no Go reader for
            # inbound_fallback_*), fallbackOn (toggle for the dropped fallback).
            "tamListenAddr", "tamListenPort", "tamPublicPort",
            "tamPriv", "tamPub", "tamCert", "tamKey",
            "tamMasq", "tamMasqPool", "tamBootstrap", "tamFp",
            "tamMaxStreams", "tamJitter",
            "setGeoipUrl", "setGeositeUrl", "tamUri",
            "wgTurnEnabled", "wgTurnListen", "wgTurnPassword", "wgTurnOutboundTag",
            "wgTurnWGPort", "wgTurnConfigDir", "wgTurnSubnet", "wgTurnServerIP",
            # Panel block — keys consumed by loadSettings + savePanel.
            "setPanelHostname", "setPanelPort", "setPanelBasePath",
            "setPanelTlsCert", "setPanelTlsKey",
            "setPanelAdmins", "setPanelServiceName",
            "setTestTarget", "setPanelVersion",
            # Broadcast.
            "setBroadcastText",
        ]
        missing = [f'id="{i}"' for i in ids_used_by_js if f'id="{i}"' not in self.html]
        self.assertEqual(missing, [],
                         f"PANEL_HTML missing field IDs the JS handlers reference: {missing}")

    def test_operator_overrides_applied(self):
        """Per the porting spec: drop sub-rail search box + ⌘K hotkey.

        2026-05-25 cleanup: Anti-DPI block (Server jitter slider + fallback)
        and Danger zone block (Reset all traffic counters button) were
        removed from Settings. The dangerResetCounters() JS stub is kept
        as a no-op for backward-compat with any external override; the
        underlying /api/reset-all endpoint also still exists. The Pool
        variant V1/V2/V3 segmented control and the Per-user TCP/UDP stream
        rows were dropped too.
        """
        # Sub-rail search box is gone — the legacy IDs from the original
        # mockup must NOT appear.
        self.assertNotIn('id="searchInput"', self.html,
                         "Sub-rail search input must be dropped (operator override)")
        self.assertNotIn('class="sub-search"', self.html,
                         "Sub-rail search wrapper must be dropped (operator override)")
        # Visible UI labels that were removed must NOT render. We assert
        # against the rendered widget shell rather than the bare phrase so
        # historical HTML comments / commit-trail references inside the
        # file don't trip the test.
        for s in (
                '<div class="lbl">Pool variant',
                '<div class="lbl">Per-user TCP streams',
                '<div class="lbl">Per-user UDP streams',
                '<div class="lbl">Server jitter',
                "<h2>Anti-DPI",
                "<h2>Danger zone",
                '<div class="lbl">Reset all traffic counters',
                'id="poolVarSeg"',
                'onclick="dangerResetCounters()"',
        ):
            self.assertNotIn(s, self.html,
                             f"removed UI marker {s!r} still rendered in PANEL_HTML")
        # JS stub kept (no UI caller, harmless).
        self.assertIn("dangerResetCounters()", self.html)


class SettingsSavePropagationTests(unittest.TestCase):
    """End-to-end behaviour: a UI save round-trips through the real
    put_inbound_settings + put_panel_settings code paths and lands in
    the DB. Asserts that the legacy handlers (saveTamizdatServer +
    savePanel) still target the right keys after the mockup port.
    """
    @classmethod
    def setUpClass(cls):
        cls.panel = PanelShortidTests.panel

    def setUp(self):
        # Wipe the keys we touch so each test starts deterministic.
        keys = (
            "inbound_masquerade_domain", "inbound_listen_port",
            "inbound_listen_addr", "inbound_jitter_ms",
            "panel_hostname", "panel_port", "panel_base_path",
            "wgturn_enabled", "wgturn_listen", "wgturn_wg_port", "wgturn_outbound_tag",
        )
        with self.panel.db_conn() as con:
            for k in keys:
                con.execute("DELETE FROM settings WHERE key=?", (k,))
        self.panel.ensure_db()

    def test_save_tamizdat_payload_round_trips(self):
        """The same JSON shape saveTamizdatServer() POSTs (camel_case /
        unprefixed keys) is accepted by the PUT-/api/tamizdat mapping
        layer and persists to inbound_* DB rows."""
        # Mirror saveTamizdatServer's payload shape one-for-one. Note:
        # the HTTP do_PUT layer does the json-key → inbound_* mapping,
        # but we can simulate it by replaying the same dict and calling
        # put_inbound_settings with the prefixed keys.
        flat = {
            "inbound_listen_addr":       "0.0.0.0",
            "inbound_listen_port":       "7790",
            "inbound_masquerade_domain": "selftest.example.com",
            "inbound_jitter_ms":         "5",
            "wgturn_enabled":            "1",
            "wgturn_listen":             "0.0.0.0:5000",
            "wgturn_wg_port":            "56001",
            "wgturn_outbound_tag":       "fallback-example",
        }
        changed = self.panel.put_inbound_settings(flat)
        self.assertIn("inbound_masquerade_domain", changed)
        self.assertIn("inbound_listen_port", changed)
        s = self.panel.get_inbound_settings()
        self.assertEqual(s["inbound_masquerade_domain"], "selftest.example.com")
        self.assertEqual(s["inbound_listen_port"], "7790")
        self.assertEqual(s["inbound_jitter_ms"], "5")
        self.assertEqual(s["wgturn_enabled"], "1")
        self.assertEqual(s["wgturn_listen"], "0.0.0.0:5000")
        self.assertEqual(s["wgturn_wg_port"], "56001")
        self.assertEqual(s["wgturn_outbound_tag"], "fallback-example")

    def test_save_panel_payload_round_trips(self):
        """settingsSaveAll → savePanel JSON shape persists to panel_* rows."""
        result = self.panel.put_panel_settings({
            "panel_hostname":  "mockup-port.example.com",
            "panel_port":      "9991",
            "panel_base_path": "/mockup-test",
        })
        self.assertTrue(result["restart_required"],
                        "port + base_path changes must flag restart_required")
        with self.panel.db_conn() as con:
            got = {
                r["key"]: r["value"]
                for r in con.execute(
                    "SELECT key, value FROM settings WHERE key IN "
                    "('panel_hostname','panel_port','panel_base_path')").fetchall()
            }
        self.assertEqual(got["panel_hostname"],  "mockup-port.example.com")
        self.assertEqual(got["panel_port"],      "9991")
        self.assertEqual(got["panel_base_path"], "/mockup-test")


class PanelCredentialAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(PanelShortidTests, "panel"):
            PanelShortidTests.setUpClass()
        cls.panel = PanelShortidTests.panel
        cls.panel.ensure_db()

    def setUp(self):
        with self.panel.db_conn() as con:
            con.execute("DELETE FROM panel_sessions")
            con.execute("DELETE FROM panel_admins")
        self.panel.sessions.clear()

    def test_panel_admin_password_hash_round_trips_without_plaintext(self):
        self.panel.set_panel_admin("panel-admin", "correct horse battery staple")
        self.assertTrue(self.panel.check_panel_password("panel-admin", "correct horse battery staple"))
        self.assertFalse(self.panel.check_panel_password("panel-admin", "wrong password"))
        self.assertFalse(self.panel.check_panel_password("missing", "correct horse battery staple"))
        with self.panel.db_conn() as con:
            row = con.execute("SELECT password_hash FROM panel_admins WHERE username=?", ("panel-admin",)).fetchone()
        self.assertIsNotNone(row)
        stored = row["password_hash"]
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertNotIn("correct horse", stored)

    def test_cli_set_admin_reads_password_stdin_and_updates_panel_port(self):
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        try:
            sys.stdin = io.StringIO("cli-password\n")
            sys.stdout = io.StringIO()
            handled = self.panel._handle_cli_args([
                "--panel-port", "9091",
                "--panel-bind-addr", "0.0.0.0",
                "--set-admin", "cli-admin",
                "--password-stdin",
            ])
        finally:
            sys.stdin = old_stdin
            sys.stdout = old_stdout
        self.assertTrue(handled)
        self.assertTrue(self.panel.check_panel_password("cli-admin", "cli-password"))
        with self.panel.db_conn() as con:
            got = {
                r["key"]: r["value"]
                for r in con.execute(
                    "SELECT key, value FROM settings WHERE key IN ('panel_port','panel_bind_addr')"
                ).fetchall()
            }
        self.assertEqual(got["panel_port"], "9091")
        self.assertEqual(got["panel_bind_addr"], "0.0.0.0")

    def test_linux_password_auth_code_removed(self):
        with open(PANEL_PY, "r", encoding="utf-8") as f:
            source = f.read()
        forbidden = ["check_linux_password", "import PAM", "/etc/shadow", "unix_chkpwd", "TAMIZDAT_PANEL_ALLOWED_USERS"]
        self.assertEqual([s for s in forbidden if s in source], [])


class OutboundBalancerUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(PanelShortidTests, "panel"):
            PanelShortidTests.setUpClass()
        cls.panel = PanelShortidTests.panel
        cls.html = cls.panel.PANEL_HTML

    def test_balancer_edit_reuses_form_modal_not_json_editor(self):
        markers = [
            'id="balOldTag"',
            'id="balModalTitle"',
            'id="balSubmitBtn"',
            'id="balOrder"',
            'id="balHighRttEnabled"',
            'id="balRttThresholdMs"',
            "function openEditBalancer",
            "function moveBalancerMember",
            "function _currentBalancerMembers",
            "failover_on_high_rtt",
            "rtt_threshold_ms",
            "Priority order",
            "#1 is tried first",
            "if(typ==='balancer'){openEditBalancer(o);return}",
            "const method = editing ? 'PUT' : 'POST'",
            "H+'/api/outbounds/'+encodeURIComponent(oldTag)",
        ]
        missing = [m for m in markers if m not in self.html]
        self.assertEqual(missing, [], f"Balancer edit UI missing markers: {missing}")
        self.assertNotIn("Balancer JSON or balancer:// URI", self.html)

    def test_balancer_high_rtt_failover_config_round_trips(self):
        cfg = self.panel.make_balancer_config({
            "tag": "bal",
            "mode": "alive",
            "outbounds": ["direct"],
            "failover_on_high_rtt": True,
            "rtt_threshold_ms": 750,
        })
        payload = json.loads(cfg["uri"])
        self.assertTrue(payload["failover_on_high_rtt"])
        self.assertEqual(payload["rtt_threshold_ms"], 750)
        parsed = self.panel.parse_balancer_config(cfg["uri"], tag_override="bal")
        self.assertTrue(parsed["failover_on_high_rtt"])
        self.assertEqual(parsed["rtt_threshold_ms"], 750)

    def test_api_outbound_entry_surfaces_balancer_high_rtt_fields(self):
        entry = self.panel.outbound_api_entry({
            "tag": "balancer",
            "type": "balancer",
            "kind": "balancer",
            "server": "balancer",
            "server_port": 0,
            "mode": "alive",
            "outbounds": ["gateway", "backup"],
            "failover_on_high_rtt": True,
            "rtt_threshold_ms": 500,
        }, {})
        self.assertTrue(entry["failover_on_high_rtt"])
        self.assertEqual(entry["rtt_threshold_ms"], 500)


if __name__ == "__main__":
    unittest.main()
