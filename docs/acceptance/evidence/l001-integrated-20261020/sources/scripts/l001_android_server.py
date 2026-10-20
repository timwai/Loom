#!/usr/bin/env python3
"""Run prebuilt, hash-verified Android tests on an authorized Linux Docker host.

Transfer bin/, Cargo manifests, Rust sources, binary-manifest.json and these
scripts to a private directory. Provision the labelled ReDroid container first.
This runner never accepts passwords or changes unrelated containers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from l001_android_docker import Lab, ROOT, IMAGE


class ServerLab(Lab):
    def sources(self):
        hashes = super().sources()
        for path in [Path(__file__).resolve(), ROOT / "binary-manifest.json"]:
            hashes[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes

    def ensure_container(self):
        config = json.loads(self.run("inspect-container", ["docker", "inspect", self.args.container])[0])[0]
        assert config["Config"].get("Labels", {}).get("loom.task") == "l001-android-remote"
        expected = json.loads(self.run("inspect-image", ["docker", "image", "inspect", IMAGE])[0])[0]["Id"]
        assert config["Image"] == expected and config["State"]["Running"]
        self.android("prepare-work", "mkdir", "-p", self.remote + "/tmp", root=True)
        self.android("work-owner", "chown", "-R", "2000:2000", self.remote, root=True)

    def environment(self):
        manifest = json.loads((ROOT / "binary-manifest.json").read_text())
        self.results["profile"] = "L-001-android-server-native-v1"
        self.results["source_commit"] = manifest["source_commit"]
        self.results["source_sha256"] = self.source_hashes
        self.results["binary_manifest"] = manifest
        config = json.loads(self.run("container-environment", ["docker", "inspect", self.args.container])[0])[0]
        self.results["environment"] = {
            "image": IMAGE, "image_id": config["Image"], "container": self.args.container,
            "host": self.run("host-uname", ["uname", "-a"])[0].strip(),
            "os": self.run("host-os", ["cat", "/etc/os-release"])[0],
            "pressure": self.run("host-pressure", ["cat", "/proc/pressure/memory"])[0],
            "resources": {k: config["HostConfig"][k] for k in ("NanoCpus", "Memory", "PidsLimit", "Privileged")},
            "ports": config["HostConfig"]["PortBindings"],
            "docker": self.run("docker-version", ["docker", "version", "--format", "{{json .}}"])[0],
        }
        self.results["framework"] = {}
        for prop in ("sys.boot_completed", "init.svc.lmkd", "ro.product.cpu.abi", "ro.build.version.sdk"):
            self.results["framework"][prop] = self.android("prop-" + prop.replace(".", "-"), "getprop", prop)[0].strip()
        assert self.results["framework"]["sys.boot_completed"] == "1"
        assert self.results["framework"]["init.svc.lmkd"] == "running"
        assert self.results["framework"]["ro.product.cpu.abi"] == "arm64-v8a"
        self.android("android-environment", "sh", "-c",
            "id; getprop ro.build.fingerprint; getenforce; cat /proc/pressure/memory; "
            "cat /sys/fs/cgroup/pids.events; cat /sys/fs/cgroup/memory.events; ip -4 route show table all")

    def build_and_test(self):
        manifest = self.results["binary_manifest"]
        for filename, digest in manifest["source_sha256"].items():
            assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == digest, filename
        suites = []
        for item in manifest["binaries"]:
            path = ROOT / "bin" / item["file"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
            destination = self.remote + "/" + item["file"]
            self.copy_in(path, destination)
            self.android("binary-mode", "chmod", "755", destination, root=True)
            if item["kind"] == "test":
                output = self.android("test-" + item["name"], destination, "--test-threads=2", timeout=240)[0]
                match = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", output)
                assert match and int(match[2]) == int(match[3]) == 0
                assert int(match[1]) == item["expected_tests"], item["name"]
                suites.append({"name": item["name"], "passed": int(match[1]), "sha256": item["sha256"]})
        self.results["tests"] = {"passed": sum(x["passed"] for x in suites), "failed": 0,
                                 "execution_uid": 2000, "suites": suites}

    def benchmarks(self):
        self.results["benchmarks"]["android-codec"] = self.storage("android-codec", "codec")
        self.results["benchmarks"]["android-storage"] = self.storage("android-storage", "bench", self.remote + "/bench.sqlite", 100)
        fixtures = self.remote + "/fixtures"
        channel = self.remote + "/l001_channel_lab"
        self.android("android-fixtures", channel, "fixture", fixtures)
        host_fixtures = self.output / "private-fixtures"
        self.run("copy-fixtures", ["docker", "cp", f"{self.args.container}:{fixtures}", str(host_fixtures)])
        host_channel = ROOT / "bin/linux_channel_lab"
        assert hashlib.sha256(host_channel.read_bytes()).hexdigest() == self.results["binary_manifest"]["linux_channel_sha256"]
        host_channel.chmod(0o755)
        config = json.loads(self.run("network-config", ["docker", "inspect", self.args.container])[0])[0]
        network = next(iter(config["NetworkSettings"]["Networks"].values()))
        self.start_server("android-server", ["docker", "exec", "--user", "2000:2000", self.args.container,
            "sh", "-c", f"echo $$ > {self.remote}/server.pid; exec {channel} server 0.0.0.0:18443 {fixtures}"])
        self.start_server("host-server", [str(host_channel), "server", f"{network['Gateway']}:18444", str(host_fixtures)])
        try:
            for name, address, native in [
                ("android-android", "127.0.0.1:18443", True),
                ("android-linux", f"{network['Gateway']}:18444", True),
                ("linux-android", "127.0.0.1:18443", False),
            ]:
                for mode in ("rejections", "bench"):
                    if native:
                        out = self.android(f"{name}-{mode}", channel, mode, address, fixtures, timeout=150)[0]
                    else:
                        out = self.run(f"{name}-{mode}", [str(host_channel), mode, address, str(host_fixtures)], timeout=150)[0]
                    self.results["benchmarks"][f"{name}-{mode}"] = json.loads(out)
        finally:
            shutil.rmtree(host_fixtures, ignore_errors=True)
            self.android("remove-android-fixtures", "rm", "-rf", fixtures)

    def validate(self):
        assert self.results["binary_manifest"]["schema"] == 2
        assert self.results["tests"]["passed"] == self.results["binary_manifest"]["expected_test_count"] >= 248
        assert self.results["tests"]["failed"] == 0
        for name in ("android-android", "android-linux", "linux-android"):
            bench = self.results["benchmarks"][name + "-bench"]
            assert bench["payload_verified"] and bench["lab_only"]
            cases = self.results["benchmarks"][name + "-rejections"]["negative_cases"]
            assert len(cases) == 5 and all(c["rejected"] for c in cases)
        assert len(self.results["storage_faults"]["sigkill_restart_trials"]) == 3
        assert len(self.results["quorum_faults"]["checks"]) == 10
        self.results["framework"]["final_lmkd"] = self.android("final-lmkd", "getprop", "init.svc.lmkd")[0].strip()
        assert self.results["framework"]["final_lmkd"] == "running"
        self.results["real_device"] = False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--container", default="loom-l001-android-jp")
    args = p.parse_args()
    args.action = "test"
    ServerLab(args).execute()


if __name__ == "__main__":
    main()
