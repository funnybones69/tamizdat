#!/usr/bin/env python3
"""Static smoke tests for the release-bundle installer scripts."""
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = ROOT / "scripts" / "install.sh"
UNINSTALL = ROOT / "scripts" / "uninstall.sh"
MANAGER = ROOT / "scripts" / "tamizdat"
PACKAGE = ROOT / "scripts" / "package-linux.sh"
PACKAGE_WINDOWS = ROOT / "scripts" / "package-windows.sh"
PACKAGE_CHECKSUMS = ROOT / "scripts" / "package-checksums.sh"


class InstallerTests(unittest.TestCase):
    def test_scripts_exist_and_are_shell_syntax_valid(self):
        for path in [INSTALL, UNINSTALL, MANAGER, PACKAGE, PACKAGE_WINDOWS, PACKAGE_CHECKSUMS]:
            self.assertTrue(path.exists(), f"{path} must exist")
            subprocess.run(["bash", "-n", str(path)], check=True)

    def test_installer_release_defaults_and_prompts(self):
        text = INSTALL.read_text(encoding="utf-8")
        for marker in [
            # interactive prompts
            "Panel port",
            "Panel username",
            "Panel password",
            "Panel URL base path",
            # two-service wiring retained
            "tamizdat-server-app",
            "tamizdat-panel",
            "TAMIZDAT_SERVER_SERVICE_NAME",
            "TAMIZDAT_PANEL_SERVICE_NAME",
            "--set-admin",
            # release defaults: VPN on 0.0.0.0:443, random panel base_path
            "0.0.0.0",
            "VPN_PORT=${TAMIZDAT_VPN_PORT:-443}",
            "--inbound-listen-port",
            "--inbound-listen-addr",
            "--panel-base-path",
            # S-UI-like packaging: tarball, app dir, management command, Linux client
            "tamizdat-linux-${ARCH}.tar.gz",
            "APP_DIR=${TAMIZDAT_APP_DIR:-/usr/local/tamizdat}",
            "COMMAND_BIN=${TAMIZDAT_COMMAND_BIN:-/usr/bin/tamizdat}",
            "tamizdat-client",
            "TAMIZDAT_INSTALL_CLIENT",
            "download_release_bundle",
            "bundle_is_complete",
            "find_local_bundle",
            "TAMIZDAT_UNINSTALL_SRC",
        ]:
            self.assertIn(marker, text, f"install.sh missing marker: {marker!r}")

    def test_installer_supports_noninteractive_mode(self):
        text = INSTALL.read_text(encoding="utf-8")
        for marker in [
            "TAMIZDAT_INSTALL_NONINTERACTIVE",
            "TAMIZDAT_INSTALL_PORT",
            "TAMIZDAT_INSTALL_USERNAME",
            "TAMIZDAT_INSTALL_PASSWORD",
            "TAMIZDAT_INSTALL_BASE_PATH",
            "TAMIZDAT_PANEL_SERVER_HOST",
        ]:
            self.assertIn(marker, text, f"install.sh missing env marker: {marker!r}")

    def test_uninstaller_supports_purge_and_removes_units_and_app_dir(self):
        text = UNINSTALL.read_text(encoding="utf-8")
        for marker in ["--purge", "tamizdat-server-app", "tamizdat-panel", "daemon-reload", "/usr/local/tamizdat", "/usr/bin/tamizdat"]:
            self.assertIn(marker, text, f"uninstall.sh missing marker: {marker!r}")

    def test_manager_command_has_expected_subcommands(self):
        text = MANAGER.read_text(encoding="utf-8")
        for marker in ["tamizdat status", "tamizdat panel-url", "tamizdat logs", "tamizdat uninstall", "restart", "version", "Secrets are not printed"]:
            self.assertIn(marker, text, f"tamizdat command missing marker: {marker!r}")

    def test_package_script_builds_expected_asset_name(self):
        text = PACKAGE.read_text(encoding="utf-8")
        for marker in ["tamizdat-${GOOS}-${GOARCH}.tar.gz", "install.sh", "SHA256SUMS", "tamizdat-server-app", "tamizdat-client", "tamizdat-panel.py", "uninstall.sh"]:
            self.assertIn(marker, text, f"package-linux.sh missing marker: {marker!r}")


if __name__ == "__main__":
    unittest.main()
