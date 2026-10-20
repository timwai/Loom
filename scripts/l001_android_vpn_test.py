#!/usr/bin/env python3
"""Exercise the standalone VPN API lab through ADB, including real consent UI.

Requires an installed debug APK and the private UDP echo helper. No appops VPN
grant is used. The probe routes only its own UID to the supplied Docker gateway.
"""
import argparse
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "fun.loom.lab"


class VpnLab:
    def __init__(self, args):
        self.args = args
        self.output = ROOT / "target/android-vpn-lab" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        (self.output / "logs").mkdir(parents=True)
        self.prefix = [str(args.adb), "-s", args.serial]
        self.results = {"profile": "L-001-android-rust-jni-vpn-lab-v2", "state": "running",
                        "started_utc": datetime.now(timezone.utc).isoformat(),
                        "cases": {}, "commands": [], "real_device": False,
                        "rust_jni_integrated": True, "rust_jni_scope": ["membership_verification", "tun_packet_validation", "protected_socket_factory"], "production_vpn": False,
                        "platform_android_acceptance": "blocked"}
        self.results["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def run(self, name, *args, expected=0, timeout=25):
        arguments = list(map(str, args))
        if arguments and arguments[0] == "shell":
            arguments = ["shell", "-T", shlex.join(arguments[1:])]
        command = self.prefix + arguments
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        log = f"logs/{len(self.results['commands']):03d}-{name}.log"
        (self.output / log).write_text(result.stdout + "\nSTDERR:\n" + result.stderr)
        self.results["commands"].append({"name": name, "argv": command, "exit_code": result.returncode, "log": log})
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f"{name}: {result.returncode}: {result.stderr}")
        return result.stdout

    def state(self):
        data = self.run("app-state", "shell", "run-as", PACKAGE, "cat", "files/result.json", expected=None)
        try:
            return json.loads(data)
        except ValueError:
            return {}

    def wait_state(self, target):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = self.state()
            if state.get("state") == target:
                return state
            if state.get("state") == "failed":
                raise RuntimeError(str(state))
            time.sleep(0.3)
        raise TimeoutError(f"state {target} not reached: {self.state()}")

    def launch(self, mode):
        self.run("stop-previous-probe", "shell", "am", "force-stop", PACKAGE)
        self.run("close-old-consent-dialog", "shell", "am", "force-stop", "com.android.vpndialogs")
        self.run("launch-" + mode, "shell", "am", "start", "-W", "-f", "0x10008000", "-n", PACKAGE + "/.ProbeActivity",
                 "--es", "mode", mode, "--es", "echo_host", self.args.echo_host,
                 "--ei", "echo_port", self.args.echo_port)

    def ui(self, name):
        self.run(name + "-dump", "shell", "uiautomator", "dump", "/data/local/tmp/loom-vpn-ui.xml")
        xml = self.run(name + "-xml", "shell", "cat", "/data/local/tmp/loom-vpn-ui.xml")
        (self.output / (name + ".xml")).write_text(xml)
        screenshot = subprocess.run(self.prefix + ["exec-out", "screencap", "-p"], capture_output=True, timeout=15, check=True)
        (self.output / (name + ".png")).write_bytes(screenshot.stdout)
        return ET.fromstring(xml)

    def tap_node(self, node):
        values = list(map(int, re.findall(r"\d+", node.attrib["bounds"])))
        assert len(values) == 4 and node.attrib.get("enabled") == "true"
        self.run("tap", "shell", "input", "tap", (values[0] + values[2]) // 2, (values[1] + values[3]) // 2)

    def consent(self, accept):
        ui = self.ui("consent-accept" if accept else "consent-cancel")
        nodes = list(ui.iter("node"))
        assert any(n.get("package") == "com.android.vpndialogs" and "Loom VPN Lab" in n.get("text", "") for n in nodes)
        resource = "android:id/button1" if accept else "android:id/button2"
        button = next(n for n in nodes if n.get("resource-id") == resource)
        self.tap_node(button)

    def interfaces(self):
        data = self.run("interfaces", "shell", "ip", "-o", "link", "show")
        return sorted(re.findall(r"^\d+: (tun\d+):", data, flags=re.MULTILINE))

    def wait_no_tun(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if not self.interfaces():
                return
            time.sleep(0.3)
        raise RuntimeError("TUN interface retained after cleanup")

    def verify_path(self, value):
        for field in ("foreground_started", "prepared_after_consent", "protect_before_connect", "tun_established",
                      "vpn_network_active", "vpn_ready_callback",
                      "protected_socket_bypasses_tun", "unprotected_udp_captured_in_tun", "unprotected_udp_echo_absent",
                      "rust_jni_membership_verified", "rust_tun_packet_validated", "rust_protect_before_connect",
                      "rust_protected_socket_closed", "rust_protect_false_refused_before_io", "rust_refused_socket_closed"):
            assert value.get(field) is True, (field, value)
        for name in ("bad_signature", "wrong_space", "stale_sequence", "expired", "truncated", "oversized"):
            assert value.get("rust_refused_" + name) is True
        assert value["uid"] >= 10000

    def hold(self):
        self.launch("hold")
        if self.state().get("prepare_requires_consent"):
            self.consent(True)
        state = self.wait_state("holding")
        self.verify_path(state)
        assert len(self.interfaces()) == 1
        return state

    def execute(self):
        try:
            assert not self.interfaces(), "another VPN exists in this Android test device"
            build = json.loads((self.args.apk.parent / "build.json").read_text())
            assert hashlib.sha256(self.args.apk.read_bytes()).hexdigest() == build["apk_sha256"]
            for filename, digest in build["source_sha256"].items():
                assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == digest, filename
            self.results["apk_build"] = build
            self.run("remove-old-lab-apk", "uninstall", PACKAGE, expected=None)
            self.run("install-lab-apk", "install", "--no-incremental", self.args.apk)
            self.run("device", "shell", "sh", "-c", "getprop ro.build.fingerprint; getprop init.svc.lmkd; pidof system_server")
            self.launch("denied")
            denied = self.wait_state("passed")
            assert denied["prepare_requires_consent"] and denied["unprepared_establish_refused"]
            self.results["cases"]["unprepared_establish_refused"] = denied
            self.launch("probe")
            self.consent(False)
            denied = self.wait_state("consent_denied")
            assert denied["consent_result_ok"] is False
            self.results["cases"]["system_consent_cancel"] = denied
            self.wait_no_tun()
            self.launch("probe")
            self.consent(True)
            healthy = self.wait_state("passed")
            self.verify_path(healthy)
            assert healthy["tun_fd_closed"] and healthy["protected_socket_closed"]
            self.results["cases"]["consent_tun_protect_and_cleanup"] = healthy
            self.wait_no_tun()
            self.hold()
            self.run("vpn-management-before-revoke", "shell", "dumpsys", "vpn_management")
            self.run("open-vpn-settings", "shell", "am", "start", "-W", "-a", "android.settings.VPN_SETTINGS")
            ui = self.ui("vpn-settings")
            label = next(n for n in ui.iter("node") if n.get("text") == "Loom VPN Lab")
            self.tap_node(label)
            ui = self.ui("vpn-disconnect")
            disconnect = next(n for n in ui.iter("node") if n.get("text", "").casefold() == "disconnect")
            self.tap_node(disconnect)
            revoked = self.wait_state("revoked")
            assert revoked["on_revoke"] and revoked["tun_fd_closed"] and revoked["protected_socket_closed"]
            self.results["cases"]["system_settings_disconnect"] = revoked
            self.wait_no_tun()
            holding = self.hold()
            pid = int(self.run("app-pid", "shell", "pidof", PACKAGE).strip())
            self.run("kill-app-process", "shell", "run-as", PACKAGE, "kill", "-9", pid)
            self.wait_no_tun()
            time.sleep(3)
            assert not self.run("no-unrequested-app-restart", "shell", "pidof", PACKAGE, expected=None).strip()
            assert not self.interfaces()
            self.run("vpn-management-after-kill", "shell", "dumpsys", "vpn_management")
            self.results["cases"]["app_sigkill_removes_tun"] = {
                "signal": "SIGKILL", "pid": pid, "tun_removed": True,
                "no_unrequested_restart_after_seconds": 3, "before_kill": holding}
            assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == self.results["runner_sha256"]
            self.results["state"] = "passed"
        except Exception as error:
            self.results["state"] = "failed"
            self.results["error"] = str(error)
            raise
        finally:
            self.run("final-force-stop", "shell", "am", "force-stop", PACKAGE, expected=None)
            self.run("app-log", "shell", "logcat", "-d", "-s", "LoomVpnLab:I", expected=None)
            self.results["finished_utc"] = datetime.now(timezone.utc).isoformat()
            (self.output / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")
            print(self.output / "results.json", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--adb", type=Path, default=Path.home() / "Library/Android/sdk/platform-tools/adb")
    p.add_argument("--serial", default="127.0.0.1:15556")
    p.add_argument("--echo-host", required=True)
    p.add_argument("--echo-port", type=int, default=19999)
    p.add_argument("--apk", type=Path, default=ROOT / "target/android-vpn-lab/loom-vpn-lab.apk")
    VpnLab(p.parse_args()).execute()


if __name__ == "__main__":
    main()
