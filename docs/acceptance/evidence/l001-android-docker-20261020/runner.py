#!/usr/bin/env python3
"""Android/Bionic laboratory on local ARM64 Docker; never release acceptance."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import subprocess
import shutil
import time

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "redroid/redroid@sha256:0a611199ba2e0b5d60af39b3327a517f6407231f4352114ed3bd3cbfe2be69aa"
LABEL = "l001-android-docker"
TARGET = "aarch64-linux-android"


class Lab:
    def __init__(self, args):
        self.args = args
        self.token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.output = ROOT / "target/l001-android-docker" / self.token
        (self.output / "logs").mkdir(parents=True)
        self.remote = f"/data/local/tmp/loom-l001/{self.token}"
        self.env = os.environ.copy()
        self.results = {
            "profile": "L-001-android-bionic-docker-v1", "started_utc": self.token,
            "state": "running", "release_state": "blocked", "commands": [],
            "benchmarks": {}, "performance_thresholds": None,
            "platform_android_acceptance": "blocked", "production_admission_enabled": False,
        }
        self.source_hashes = self.sources()
        self.processes = []

    def sources(self):
        paths = [ROOT / "Cargo.lock", ROOT / "Cargo.toml", Path(__file__).resolve()]
        paths += sorted((ROOT / "crates").rglob("*.rs"))
        paths += sorted((ROOT / "crates").rglob("Cargo.toml"))
        return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in paths if "target" not in p.relative_to(ROOT).parts}

    def run(self, name, argv, *, expected=0, timeout=60):
        print(name, flush=True)
        started = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.env, capture_output=True,
                                    text=True, timeout=timeout)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout = (error.stdout or b"").decode(errors="replace")
            stderr = (error.stderr or b"").decode(errors="replace") + "\nCOMMAND TIMEOUT"
            code = 124
        path = f"logs/{len(self.results['commands']):03d}-{name}.log"
        (self.output / path).write_text(stdout + "\nSTDERR:\n" + stderr)
        self.results["commands"].append({"name": name, "argv": list(map(str, argv)),
                                         "exit_code": code, "expected": expected,
                                         "elapsed_s": time.monotonic() - started, "log": path})
        if expected is not None and code != expected:
            raise RuntimeError(f"{name}: exit {code}, expected {expected}: {stderr[-1000:]}")
        return stdout, stderr, code

    def android(self, name, *args, root=False, **kwargs):
        # docker exec does not inherit Android init's exported APEX roots.
        # Platform sqlite3 needs both I18N and TZDATA or ICU aborts on open.
        command = ["docker", "exec", "-e", "ANDROID_ROOT=/system", "-e", "ANDROID_DATA=/data",
                   "-e", "ANDROID_ART_ROOT=/apex/com.android.art", "-e", "ANDROID_I18N_ROOT=/apex/com.android.i18n",
                   "-e", "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata"]
        if not root:
            command += ["--user", "2000:2000", "-e", f"TMPDIR={self.remote}/tmp"]
        return self.run(name, [*command, self.args.container, *map(str, args)], **kwargs)

    def storage(self, name, *args, error=None):
        out, err, code = self.android(name, f"{self.remote}/l001_storage_lab", *args,
                                     expected=1 if error else 0)
        if error:
            if error not in err:
                raise AssertionError(f"expected {error}, got {err}")
            return {"rejected": True, "reason": error, "exit_code": code}
        return json.loads(out)

    def copy_in(self, path, destination):
        self.run("copy-" + Path(path).name, ["docker", "cp", str(path),
                                           f"{self.args.container}:{destination}"])

    def ensure_container(self):
        out, _, code = self.run("inspect-container", ["docker", "inspect", self.args.container], expected=None)
        if code:
            architecture = self.run("docker-architecture", ["docker", "info", "--format", "{{.Architecture}}"])[0].strip()
            if architecture not in ("aarch64", "arm64"):
                raise RuntimeError("this pinned laboratory image requires ARM64 Docker")
            self.run("pull-android", ["docker", "pull", "--platform", "linux/arm64", IMAGE], timeout=1200)
            self.run("create-android", [
                "docker", "run", "-d", "--name", self.args.container,
                "--label", f"loom.task={LABEL}", "--platform", "linux/arm64",
                "--privileged", "--cpus=4", "--memory=4g", "--pids-limit=1024", "--restart=no",
                "-p", "127.0.0.1:15555:5555", "-p", "127.0.0.1:18443:18443",
                "-v", "loom-l001-android-data:/data", IMAGE,
                "androidboot.use_memfd=1", "androidboot.redroid_gpu_mode=guest",
                "androidboot.redroid_width=720", "androidboot.redroid_height=1280",
                "androidboot.redroid_fps=15",
            ])
        else:
            config = json.loads(out)[0]
            if config["Config"].get("Labels", {}).get("loom.task") != LABEL:
                raise RuntimeError("refusing to change a container not owned by this laboratory")
            expected_image = json.loads(self.run("pinned-image", ["docker", "image", "inspect", IMAGE])[0])[0]["Id"]
            if config["Image"] != expected_image:
                raise RuntimeError("existing Android container does not match pinned image")
            if not config["State"]["Running"]:
                self.run("start-android", ["docker", "start", self.args.container])
        # OrbStack exposes built-in Binder devices with mode 0600. Only fix the
        # nodes in this container; do not mount the Docker socket or host files.
        for attempt in range(20):
            _, _, code = self.android("binder-permissions", "chmod", "666", "/dev/binder",
                                      "/dev/hwbinder", "/dev/vndbinder", root=True, expected=None)
            if code == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Android Binder devices unavailable")
        self.android("prepare-work", "mkdir", "-p", self.remote + "/tmp", root=True)
        self.android("work-owner", "chown", "-R", "2000:2000", self.remote, root=True)

    def environment(self):
        self.results["source_commit"] = self.run("source-commit", ["git", "rev-parse", "HEAD"])[0].strip()
        self.results["source_sha256"] = self.source_hashes
        config = json.loads(self.run("container-environment", ["docker", "inspect", self.args.container])[0])[0]
        self.results["environment"] = {
            "image": IMAGE, "image_id": config["Image"], "container": self.args.container,
            "resources": {key: config["HostConfig"][key] for key in ("NanoCpus", "Memory", "PidsLimit", "Privileged")},
            "ports": config["HostConfig"]["PortBindings"],
            "docker": self.run("docker-version", ["docker", "version", "--format", "{{json .}}"])[0].strip(),
            "host": self.run("host", ["uname", "-a"])[0].strip(),
            "rust": self.run("rust", ["rustc", "--version", "--verbose"])[0].strip(),
        }
        script = ("id; uname -a; getprop ro.build.version.release; getprop ro.build.version.sdk; "
                  "getprop ro.product.cpu.abi; getprop ro.build.fingerprint; getenforce; "
                  "ls -l /dev/binder /dev/hwbinder /dev/vndbinder /dev/net/tun; "
                  "ip -4 route show table all; ip -4 rule; "
                  "test -e /proc/pressure/memory && echo PSI_PRESENT || echo PSI_MISSING")
        self.results["environment"]["android"] = self.android("android-environment", "sh", "-c", script)[0]
        props = {}
        for prop in ("sys.boot_completed", "init.svc.lmkd", "ro.build.version.sdk", "ro.product.cpu.abi"):
            props[prop] = self.android("prop-" + prop.replace(".", "-"), "getprop", prop)[0].strip()
        if props["ro.product.cpu.abi"] != "arm64-v8a" or props["ro.build.version.sdk"] != "34":
            raise RuntimeError("unexpected Android runtime")
        self.results["framework"] = {"properties": props, "real_device": False,
            "vpn_service_tested": False, "app_sandbox_tested": False,
            "note": "Native binaries run as shell UID 2000 via docker exec; no production Android APK/JNI exists."}
        self.results["framework"]["psi_available"] = "PSI_PRESENT" in self.results["environment"]["android"]
        adb = self.args.sdk / "platform-tools/adb"
        if adb.is_file():
            self.run("adb-connect", [str(adb), "connect", "127.0.0.1:15555"], expected=None, timeout=8)
            out, err, code = self.run("adb-shell", [str(adb), "-s", "127.0.0.1:15555", "shell", "-T", "id"], expected=None, timeout=8)
            self.results["framework"]["adb_shell_probe"] = {"exit_code": code, "stdout": out, "stderr": err}
        self.android("lmkd-diagnostic", "sh", "-c", "logcat -d -b all -s lowmemorykiller:V | tail -45", root=True)

    def build_and_test(self):
        ndk = self.args.sdk / "ndk" / self.args.ndk
        prebuilt = ndk / "toolchains/llvm/prebuilt/darwin-x86_64/bin"
        clang = prebuilt / "aarch64-linux-android26-clang"
        if not clang.is_file():
            raise RuntimeError(f"missing Android NDK compiler: {clang}")
        self.env.update({"CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": str(clang),
                         "CC_aarch64_linux_android": str(clang),
                         "AR_aarch64_linux_android": str(prebuilt / "llvm-ar")})
        self.results["environment"]["ndk"] = (ndk / "source.properties").read_text()
        self.run("ndk-clang", [str(clang), "--version"])
        self.run("rust-target", ["rustup", "target", "add", TARGET], timeout=600)
        artifact_json = self.run("build-android-tests", ["cargo", "test", "--workspace", "--all-targets",
            "--locked", "--target", TARGET, "--no-run", "--message-format=json"], timeout=900)[0]
        suites = []
        for line in artifact_json.splitlines():
            item = json.loads(line)
            if item.get("reason") != "compiler-artifact" or not item.get("profile", {}).get("test") or not item.get("executable"):
                continue
            path = Path(item["executable"])
            destination = self.remote + "/" + path.name
            self.copy_in(path, destination)
            self.android("test-mode", "chmod", "755", destination, root=True)
            output = self.android("test-" + item["target"]["name"], destination, "--test-threads=2", timeout=180)[0]
            match = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", output)
            if not match or int(match[2]) or int(match[3]):
                raise AssertionError("incomplete Android test suite")
            suites.append({"name": item["target"]["name"], "passed": int(match[1]),
                           "binary_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if not suites or sum(x["passed"] for x in suites) == 0:
            raise AssertionError("no Android tests executed")
        self.results["tests"] = {"passed": sum(x["passed"] for x in suites), "failed": 0,
                                 "execution_uid": 2000, "suites": suites}
        self.run("build-android-release", ["cargo", "build", "--release", "--workspace", "--examples",
                                           "--locked", "--target", TARGET], timeout=900)
        self.run("build-host-channel", ["cargo", "build", "--release", "-p", "loom-transport",
                                        "--example", "l001_channel_lab", "--locked"], timeout=900)
        self.results["binary_sha256"] = {}
        for name in ("l001_channel_lab", "l001_storage_lab"):
            path = ROOT / "target" / TARGET / "release/examples" / name
            self.copy_in(path, self.remote + "/" + name)
            self.android("binary-mode", "chmod", "755", self.remote + "/" + name, root=True)
            self.results["binary_sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()

    def benchmarks(self):
        self.results["benchmarks"]["android-codec"] = self.storage("android-codec", "codec")
        self.results["benchmarks"]["android-storage"] = self.storage("android-storage", "bench", self.remote + "/bench.sqlite", 100)
        fixtures = self.remote + "/fixtures"
        channel = self.remote + "/l001_channel_lab"
        self.android("android-fixtures", channel, "fixture", fixtures)
        host_fixtures = self.output / "private-fixtures"
        self.run("copy-fixtures", ["docker", "cp", f"{self.args.container}:{fixtures}", str(host_fixtures)])
        host_channel = str(ROOT / "target/release/examples/l001_channel_lab")
        # The existing OrbStack container is reachable by its private IP. New
        # containers also publish the laboratory port only on host loopback.
        config = json.loads(self.run("network-config", ["docker", "inspect", self.args.container])[0])[0]
        if config["NetworkSettings"]["Ports"].get("18443/tcp"):
            android_address = "127.0.0.1:18443"
        else:
            ip = next(iter(config["NetworkSettings"]["Networks"].values()))["IPAddress"]
            android_address = f"{ip}:18443"
        self.start_server("android-server", ["docker", "exec", "--user", "2000:2000", self.args.container,
            "sh", "-c", f"echo $$ > {shlex.quote(self.remote + '/server.pid')}; exec {shlex.quote(channel)} server 0.0.0.0:18443 {shlex.quote(fixtures)}"])
        # Resolve host.docker.internal using Docker's own resolver without
        # depending on the Android framework DNS service.
        host_ip = self.args.host_ip
        if not host_ip:
            host_ip = self.run("resolve-host", ["docker", "run", "--rm", "--entrypoint", "getent",
                                               "loom-l001-lab:local", "ahostsv4", "host.docker.internal"])[0].split()[0]
        with socket.socket() as listener:
            listener.bind(("0.0.0.0", 0))
            host_port = listener.getsockname()[1]
        self.start_server("host-server", [host_channel, "server", f"0.0.0.0:{host_port}", str(host_fixtures)])
        try:
            for name, address, native in [("android-android", "127.0.0.1:18443", True),
                                          ("android-macos", f"{host_ip}:{host_port}", True),
                                          ("macos-android", android_address, False)]:
                for mode in ("rejections", "bench"):
                    if native:
                        out = self.android(f"{name}-{mode}", channel, mode, address, fixtures, timeout=150)[0]
                    else:
                        out = self.run(f"{name}-{mode}", [host_channel, mode, address, str(host_fixtures)], timeout=150)[0]
                    self.results["benchmarks"][f"{name}-{mode}"] = json.loads(out)
        finally:
            shutil.rmtree(host_fixtures, ignore_errors=True)
            self.android("remove-android-fixtures", "rm", "-rf", fixtures)

    def start_server(self, name, command):
        log = (self.output / "logs" / f"{name}-stderr.log").open("w")
        child = subprocess.Popen(command, cwd=ROOT, env=self.env, stdout=subprocess.PIPE, stderr=log)
        self.processes.append((name, child, log))
        if not select.select([child.stdout], [], [], 15)[0]:
            raise TimeoutError(f"{name} not ready")
        ready = child.stdout.readline().decode()
        (self.output / "logs" / f"{name}-ready.log").write_text(ready)
        if "listening" not in json.loads(ready):
            raise RuntimeError(f"{name} did not bind")

    def sqlite(self, name, path, sql):
        return self.android(name, "/system/bin/sqlite3", path, sql)[0].strip()

    def backup(self, source, destination):
        # Paths are generated internally without quotes/whitespace.
        self.sqlite("sqlite-backup", source, f".backup '{destination}'")

    def storage_faults(self):
        trials = []
        for floor in (10, 25, 50):
            path = f"{self.remote}/kill-{floor}.sqlite"
            pid_file = self.remote + "/writer.pid"
            command = f"echo $$ > {shlex.quote(pid_file)}; exec {shlex.quote(self.remote + '/l001_storage_lab')} writer {shlex.quote(path)}"
            with (self.output / "logs" / f"kill-{floor}-stderr.log").open("w") as err:
                child = subprocess.Popen(["docker", "exec", "--user", "2000:2000", self.args.container,
                                          "sh", "-c", command], stdout=subprocess.PIPE, stderr=err)
                ack = 0
                try:
                    deadline = time.monotonic() + 30
                    while ack < floor:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                            raise TimeoutError("Android journal writer failed to acknowledge")
                        line = child.stdout.readline()
                        if not line.startswith(b"ACK "):
                            raise RuntimeError("unexpected Android writer output")
                        ack = int(line.split()[1])
                    pid = int(self.android("writer-pid", "cat", pid_file)[0])
                    self.android("kill-android-writer", "kill", "-9", pid, root=True)
                    code = child.wait(timeout=10)
                    if code != 137:
                        raise AssertionError(f"writer was not SIGKILLed: {code}")
                finally:
                    if child.poll() is None:
                        # Kill the device-side process, not just docker exec.
                        self.android("cleanup-writer", "sh", "-c", f"test ! -f {pid_file} || kill -9 $(cat {pid_file})", root=True, expected=None)
                        child.wait(timeout=10)
                    child.stdout.close()
            recovered = self.storage("inspect-after-kill", "inspect", path)
            integrity = self.sqlite("integrity-check", path, "PRAGMA integrity_check")
            assert recovered["sequence"] >= ack and recovered["pending"] == recovered["sequence"]
            assert recovered["admission_paused"] and integrity == "ok"
            trials.append({"acknowledged_floor": ack, "recovered": recovered,
                           "signal": "SIGKILL", "exit_code": code, "integrity_check": integrity})
        self.results["storage_faults"] = {"sigkill_restart_trials": trials, "physical_power_loss_tested": False}
        local = self.remote + "/peer.sqlite"
        old, current = self.remote + "/old.sqlite", self.remote + "/current.sqlite"
        witnesses = [self.remote + f"/witness-{i}.sqlite" for i in (1, 2)]
        self.storage("fill-initial", "fill", local, 5)
        self.backup(local, old)
        for path in witnesses:
            self.backup(local, path)
        def replies(nonce):
            return [self.storage("witness-read", "witness-read", path, seed, nonce)
                    for path, seed in zip(witnesses, (21, 22))]
        def recover(nonce, responses, error=None):
            return self.storage("quorum-recover", "recover", local, nonce,
                                *[r["receipt"] for r in responses], error=error)
        old_replies = replies(secrets.token_hex(32))
        for path in [local, *witnesses]:
            self.storage("advance-history", "fill", path, 3)
        self.backup(local, current)
        nonce = secrets.token_hex(32)
        responses = replies(nonce)
        checks = {"current_signed_history": recover(nonce, responses)}
        assert checks["current_signed_history"]["sequence"] == 8
        self.backup(old, local)
        checks["valid_old_local_backup"] = recover(nonce, responses, "LocalRollbackOrFork")
        checks["old_signed_response_new_nonce"] = recover(nonce, old_replies, "WrongChallenge")
        checks["one_witness_offline"] = recover(nonce, responses[:1], "MissingOrDuplicateWitness")
        self.backup(current, local)
        forged = [dict(r) for r in responses]
        receipt = bytearray.fromhex(forged[0]["receipt"])
        receipt[-1] ^= 1
        forged[0]["receipt"] = receipt.hex()
        checks["forged_signature"] = recover(nonce, forged, "InvalidSignature")
        self.backup(old, witnesses[1])
        nonce = secrets.token_hex(32)
        checks["split_witness_histories"] = recover(nonce, replies(nonce), "SplitWitnesses")
        self.backup(current, witnesses[1])
        for case, sql in [
            ("local_signed_evidence_tamper", "UPDATE unified_policy_events SET evidence=zeroblob(length(evidence)) WHERE seq=1"),
            ("local_missing_outbox", "DELETE FROM unified_policy_outbox WHERE seq=1"),
        ]:
            self.sqlite("tamper-local", local, sql)
            checks[case] = recover(nonce, responses, "inspect: Conflict")
            self.backup(current, local)
        self.sqlite("tamper-witness", witnesses[0], "DELETE FROM unified_policy_outbox WHERE seq=1")
        checks["corrupt_witness_refuses_to_sign"] = self.storage("corrupt-witness", "witness-read", witnesses[0], 21,
                                                               secrets.token_hex(32), error="inspect: Conflict")
        self.backup(current, witnesses[0])
        nonce = secrets.token_hex(32)
        checks["fresh_recheck_after_repair"] = recover(nonce, replies(nonce))
        assert checks["fresh_recheck_after_repair"]["sequence"] == 8
        for path in [local, *witnesses]:
            self.backup(old, path)
        nonce = secrets.token_hex(32)
        boundary = recover(nonce, replies(nonce))
        assert boundary["sequence"] == 5 and boundary["admission_paused"]
        self.results["quorum_faults"] = {"checks": checks, "independent_storage_certified": False,
            "all_same_host_stores_rollback_counterexample": boundary}

    def cleanup(self):
        for name, child, log in reversed(self.processes):
            if name == "android-server":
                self.android("stop-android-server", "sh", "-c",
                             f"test ! -f {self.remote}/server.pid || kill $(cat {self.remote}/server.pid)",
                             root=True, expected=None)
            elif child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()
            log.close()

    def validate(self):
        assert self.results["tests"]["passed"] >= 248 and self.results["tests"]["failed"] == 0
        expected_cases = {"wrong_server_pin", "untrusted_client", "wrong_space", "wrong_epoch", "membership_denied"}
        for path in ("android-android", "android-macos", "macos-android"):
            bench = self.results["benchmarks"][path + "-bench"]
            assert bench["payload_verified"] and bench["lab_only"]
            cases = self.results["benchmarks"][path + "-rejections"]["negative_cases"]
            assert len(cases) == 5 and {c["case"] for c in cases} == expected_cases
            assert all(c["rejected"] is True for c in cases)
        for bench in self.results["benchmarks"].values():
            for metric in bench.get("metrics", []):
                assert metric["n"] == len(metric["samples"]) > 0
                assert all(math.isfinite(v) and v > 0 for v in metric["samples"])
        assert len(self.results["storage_faults"]["sigkill_restart_trials"]) == 3
        assert len(self.results["quorum_faults"]["checks"]) == 10
        assert self.results["release_state"] == "blocked" and self.results["platform_android_acceptance"] == "blocked"
        self.results["checks"] = [
            "Android/Bionic ARM64 workspace regression under shell UID 2000",
            "Three TCP/TLS 1.3 paths, verified payloads and 15 expected identity/scope refusals",
            "Android release codec and signed SQLite journal benchmark with raw samples",
            "Three SIGKILL/restart cases retain acknowledged history and pass integrity_check",
            "Ten fresh Witness recovery cases plus same-host rollback counterexample",
            "Application/VpnService, memory pressure and real-device release gates remain unverified",
        ]

    def execute(self):
        try:
            self.ensure_container()
            self.environment()
            if self.args.action == "test":
                self.build_and_test()
                self.benchmarks()
                self.storage_faults()
                if self.sources() != self.source_hashes:
                    raise RuntimeError("source files changed during Android validation")
                self.results["source_unchanged"] = True
                self.validate()
                self.results["state"] = "passed"
            else:
                self.results["state"] = "installed"
        except Exception as error:
            self.results["state"] = "failed"
            self.results["error"] = str(error)
            raise
        finally:
            self.cleanup()
            shutil.rmtree(self.output / "private-fixtures", ignore_errors=True)
            self.results["finished_utc"] = datetime.now(timezone.utc).isoformat()
            (self.output / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")
            print(self.output / "results.json", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "test"), nargs="?", default="test")
    parser.add_argument("--container", default="loom-l001-android")
    parser.add_argument("--sdk", type=Path, default=Path.home() / "Library/Android/sdk")
    parser.add_argument("--ndk", default="27.2.12479018")
    parser.add_argument("--host-ip", help="host IP reachable from Docker; default uses loom-l001-lab:local resolver")
    Lab(parser.parse_args()).execute()


if __name__ == "__main__":
    main()
