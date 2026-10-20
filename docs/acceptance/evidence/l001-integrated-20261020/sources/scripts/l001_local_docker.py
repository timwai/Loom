#!/usr/bin/env python3
"""Reproducible local/macOS + Docker/Linux L-001 evidence, never release signoff."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
BASE = "rust:1.90.0-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9"
CANARY = b"LOOM-L001-PLAINTEXT-CANARY-DO-NOT-EXPOSE"


class Relay:
    """Bounded ciphertext inspection; retained tails detect cross-read canaries."""
    def __init__(self, destination, mutate=False):
        self.destination = destination
        self.mutate = mutate
        self.bytes = 0
        self.plaintext_found = False
        self.mutated = False
        self.errors = []
        self.workers = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self.forward, args=(client,), daemon=True)
            self.workers.append(thread)
            thread.start()

    def forward(self, client):
        server = None
        try:
            server = socket.create_connection(self.destination, timeout=5)
            tails = {client: b"", server: b""}
            offset = 0
            while True:
                readable, _, _ = select.select([client, server], [], [], 10)
                if not readable:
                    raise TimeoutError("relay idle timeout")
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    self.bytes += len(data)
                    scan = tails[source] + data
                    self.plaintext_found |= CANARY in scan
                    tails[source] = scan[-len(CANARY):]
                    if source is client:
                        if self.mutate and offset <= 10 < offset + len(data):
                            data = bytearray(data)
                            data[10 - offset] ^= 1
                            self.mutated = True
                        offset += len(data)
                    (server if source is client else client).sendall(data)
        except (ConnectionError, OSError, TimeoutError) as error:
            self.errors.append(str(error))
        finally:
            client.close()
            if server:
                server.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for thread in self.workers:
            thread.join(timeout=12)
            if thread.is_alive():
                raise RuntimeError("relay thread did not terminate")


class Lab:
    def __init__(self, args):
        self.args = args
        self.token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.directory = ROOT / "target" / "l001-local-docker" / self.token
        self.directory.mkdir(parents=True, exist_ok=False)
        self.logs = self.directory / "logs"
        self.logs.mkdir()
        self.containers = []
        self.processes = []
        self.network = None
        self.builder_owned = not args.builder_container
        self.builder = args.builder_container or f"loom-l001-build-{self.token.lower()}"
        self.channel = str(ROOT / "target/release/examples/l001_channel_lab")
        self.storage = str(ROOT / "target/release/examples/l001_storage_lab")
        self.results = {"schema": 1, "started_utc": self.token, "commands": {}, "benchmarks": {}, "acceptance": {}, "release_state": "blocked", "performance_thresholds": None}

    def command(self, name, command, expected=0, timeout=600):
        print(name, flush=True)
        start = time.monotonic()
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        (self.logs / f"{name}.log").write_text(completed.stdout + "\nSTDERR:\n" + completed.stderr)
        self.results["commands"][name] = {"argv": command, "exit_code": completed.returncode, "expected_exit_code": expected, "elapsed_s": time.monotonic() - start, "log": f"logs/{name}.log"}
        if completed.returncode != expected:
            raise RuntimeError(f"{name}: expected {expected}, got {completed.returncode}: {completed.stderr[-3000:]}")
        return completed.stdout

    def docker(self, name, command, **kwargs):
        return self.command(name, ["docker", "exec", self.builder, *command], **kwargs)

    def record_json(self, name, command, docker=False):
        value = json.loads(self.docker(name, command) if docker else self.command(name, command))
        self.results["benchmarks"][name] = value
        return value

    def environment(self):
        self.results["source_commit"] = self.command("source-commit", ["git", "rev-parse", "HEAD"]).strip()
        self.command("source-diff", ["git", "diff", "--binary", "HEAD"])
        paths = []
        tracked = self.command("source-inventory", ["git", "ls-files", "--cached", "--others", "--exclude-standard"]).splitlines()
        suffixes = {".rs", ".toml", ".lock", ".py", ".go", ".kt", ".mjs", ".hex", ".Dockerfile"}
        for filename in tracked:
            path = ROOT / filename
            if path.is_file() and (path.suffix in suffixes or filename == "docs/acceptance/l001.json"):
                paths.append(path)
        self.results["source_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}
        self.results["environment"] = {
            "uname": self.command("host-uname", ["uname", "-a"]).strip(),
            "macos": self.command("host-macos", ["sw_vers"]).strip(),
            "cpu_memory": self.command("host-resources", ["sysctl", "-n", "hw.model", "hw.ncpu", "hw.memsize"]).strip(),
            "rust": self.command("host-rust", ["rustc", "--version", "--verbose"]).strip(),
            "docker": json.loads(self.command("docker-version", ["docker", "version", "--format", "{{json .}}"])),
            "docker_resources": self.command("docker-resources", ["docker", "info", "--format", "cpus={{.NCPU}} memory={{.MemTotal}} kernel={{.KernelVersion}} os={{.OperatingSystem}}"]),
            "base_image": BASE,
        }

    def prepare(self):
        if self.builder_owned:
            self.command("docker-build-lab", ["docker", "build", "-f", "scripts/l001-lab.Dockerfile", "-t", "loom-l001-lab:local", "."], timeout=1200)
            self.command("docker-start-builder", ["docker", "run", "-d", "--name", self.builder, "--label", "loom.task=l001-local-docker", "--cpus=4", "--memory=4g", "--pids-limit=512", "-v", f"{ROOT}:/workspace", "-v", "loom-l001-cargo:/usr/local/cargo/registry", "-v", "loom-l001-target:/build", "loom-l001-lab:local", "sleep", "infinity"])
            self.containers.append(self.builder)
        self.results["environment"]["builder_resources"] = json.loads(self.command("builder-resources", ["docker", "inspect", self.builder, "--format", '{{json .HostConfig}}']))
        # Keep only meaningful resource limits, never unrelated host/container configuration.
        self.results["environment"]["builder_resources"] = {key: self.results["environment"]["builder_resources"][key] for key in ["NanoCpus", "Memory", "PidsLimit"]}
        self.docker("linux-toolchains", ["sh", "-c", "rustc --version; go version; node --version; java -version; kotlinc -version; dpkg-query -W make cmake python3 nodejs default-jdk-headless kotlin"])
        # Cargo's incremental build checks source freshness even on a warm
        # cache. Never measure stale native binaries under new source hashes.
        self.command("host-release-build", ["cargo", "build", "--release", "--workspace", "--examples", "--locked"])
        self.docker("linux-release-build", ["cargo", "build", "--release", "--workspace", "--examples", "--locked"], timeout=1200)

    def checks(self):
        cargo = ["cargo", "test", "--workspace", "--all-targets", "--locked"]
        for name, docker in [("host-tests", False), ("linux-tests", True)]:
            log = self.docker(name, cargo) if docker else self.command(name, cargo)
            rows = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log)
            assert rows
            self.results["acceptance"][name] = {"passed": sum(int(row[0]) for row in rows), "failed": sum(int(row[1]) for row in rows)}
        self.command("host-format", ["cargo", "fmt", "--all", "--", "--check"])
        lint = ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"]
        self.command("host-clippy", lint)
        self.docker("linux-clippy", lint)
        self.docker("linux-doc", ["cargo", "doc", "--workspace", "--no-deps", "--locked"])
        self.command("acceptance-manifest", ["python3", "scripts/l001_gate.py"])
        self.command("release-still-refused", ["python3", "scripts/l001_gate.py", "--require-complete"], expected=1)
        for environment, docker in [("host", False), ("linux", True)]:
            for name, command in [
                ("wire-go", ["go", "run", "./interop/wire01/go/main.go", "."]),
                ("wire-js", ["node", "./interop/wire01/js/check.mjs", "."]),
                ("signature-go", ["go", "run", "./test-vectors/wire-v1/check.go"]),
                ("signature-js", ["node", "./test-vectors/wire-v1/check.mjs"]),
            ]:
                (self.docker if docker else self.command)(f"{environment}-{name}", command)
        self.docker("wire-kotlin-compile", ["kotlinc", "interop/wire01/kotlin/Main.kt", "-include-runtime", "-d", "/build/l001-wire.jar"])
        self.docker("wire-kotlin", ["java", "-jar", "/build/l001-wire.jar", "."])
        for environment, docker in [("host", False), ("linux", True)]:
            boot = ["cargo", "run", "-p", "loomd", "--locked", "--quiet"]
            output = (self.docker if docker else self.command)(f"{environment}-bootstrap", boot)
            assert "network_enabled=false" in output and "BootstrapOnly" in output
            probe = ["cargo", "run", "-p", "loom-store", "--example", "probe_tpm2", "--locked", "--quiet"]
            (self.docker if docker else self.command)(f"{environment}-tpm-refused", probe, expected=2)

    def storage_tests(self):
        self.record_json("host-codec", [self.storage, "codec"])
        self.record_json("linux-codec", ["/build/release/examples/l001_storage_lab", "codec"], docker=True)
        self.record_json("host-storage", [self.storage, "bench", str(self.directory / "bench.sqlite"), "100"])
        linux_dir = f"/build/l001-lab/{self.token}"
        self.docker("linux-mkdir", ["mkdir", "-p", linux_dir])
        self.record_json("linux-storage", ["/build/release/examples/l001_storage_lab", "bench", linux_dir + "/bench.sqlite", "100"], docker=True)
        self.results["acceptance"]["host-storage-faults"] = json.loads(self.command("host-storage-faults", ["python3", "scripts/l001_storage_faults.py", self.storage, str(self.directory / "faults")]))
        self.results["acceptance"]["linux-storage-faults"] = json.loads(self.docker("linux-storage-faults", ["python3", "/workspace/scripts/l001_storage_faults.py", "/build/release/examples/l001_storage_lab", linux_dir + "/faults"]))
        self.results["acceptance"]["host-quorum-recovery"] = json.loads(self.command("host-quorum-recovery", ["python3", "scripts/l001_quorum_faults.py", self.storage, str(self.directory / "quorum")]))
        self.results["acceptance"]["linux-quorum-recovery"] = json.loads(self.docker("linux-quorum-recovery", ["python3", "/workspace/scripts/l001_quorum_faults.py", "/build/release/examples/l001_storage_lab", linux_dir + "/quorum"]))

    def container_args(self, name, readonly=True):
        return ["docker", "run", "--rm", "--name", name, "--label", "loom.task=l001-local-docker", "--cpus=2", "--memory=512m", "--pids-limit=128", "--cap-drop=ALL", "--security-opt=no-new-privileges", *(["--read-only"] if readonly else []), "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]

    def container_crashes(self):
        trials = []
        for index, floor in enumerate([10, 25, 50]):
            name = f"loom-l001-kill-{index}-{self.token.lower()}"
            self.containers.append(name)
            path = f"/build/l001-lab/{self.token}/container-kill-{index}.sqlite"
            command = [*self.container_args(name), "--network", "none", "-v", "loom-l001-target:/build", BASE, "/build/release/examples/l001_storage_lab", "writer", path]
            with (self.logs / f"container-kill-{index}.stderr.log").open("w") as log:
                process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=log, bufsize=0)
                self.processes.append((process, log))
                acknowledged = 0
                deadline = time.monotonic() + 30
                try:
                    while acknowledged < floor:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
                            raise TimeoutError("container writer failed to acknowledge")
                        line = process.stdout.readline()
                        if not line:
                            raise RuntimeError("container writer exited early")
                        if line.startswith(b"ACK "):
                            acknowledged = int(line.split()[1])
                    self.command(f"container-kill-{index}", ["docker", "kill", "--signal=KILL", name])
                    process.wait(timeout=15)
                    assert process.returncode == 137
                finally:
                    if process.poll() is None:
                        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
                        process.wait(timeout=15)
                    process.stdout.close()
                    self.processes.remove((process, log))
                recovered = json.loads(self.docker(f"container-recovery-{index}", ["/build/release/examples/l001_storage_lab", "inspect", path]))
                assert recovered["sequence"] >= acknowledged and recovered["pending"] == recovered["sequence"] and recovered["admission_paused"]
                trials.append({"acknowledged_floor": acknowledged, "recovered": recovered, "container_exit": process.returncode, "writer_argv": command})
        self.results["acceptance"]["container-kill-restart"] = trials

    def network_tests(self):
        fixture_dir = self.directory / "fixtures"
        self.command("create-test-identities", [self.channel, "fixture", str(fixture_dir)])
        host_log = (self.logs / "host-server.log").open("w")
        host = subprocess.Popen([self.channel, "server", "0.0.0.0:0", str(fixture_dir)], stdout=subprocess.PIPE, stderr=host_log, cwd=ROOT)
        self.processes.append((host, host_log))
        ready, _, _ = select.select([host.stdout], [], [], 10)
        if not ready:
            raise TimeoutError("host server not ready")
        port = int(json.loads(host.stdout.readline())["listening"].rsplit(":", 1)[1])
        self.network = f"loom-l001-{self.token.lower()}"
        self.command("network-create", ["docker", "network", "create", "--label", "loom.task=l001-local-docker", self.network])
        server_name = f"loom-l001-server-{self.token.lower()}"
        self.containers.append(server_name)
        mounts = ["-v", "loom-l001-target:/build:ro", "-v", f"{fixture_dir}:/fixtures:ro"]
        self.command("linux-server-start", [*self.container_args(server_name), "-d", "--network", self.network, "-p", "127.0.0.1::38443", *mounts, BASE, "/build/release/examples/l001_channel_lab", "server", "0.0.0.0:38443", "/fixtures"])
        address = self.command("linux-server-port", ["docker", "port", server_name, "38443/tcp"]).strip()
        # Avoid startup timing assumptions: verify a full authenticated echo before measuring.
        self.command("host-linux-ready", [self.channel, "probe", address, str(fixture_dir)])
        def client(name, mode, endpoint):
            return [*self.container_args(f"loom-l001-client-{name}-{self.token.lower()}"), "--network", self.network, *mounts, BASE, "/build/release/examples/l001_channel_lab", mode, endpoint, "/fixtures"]
        paths = [
            ("host-host", [self.channel, "bench", f"127.0.0.1:{port}", str(fixture_dir)], [self.channel, "rejections", f"127.0.0.1:{port}", str(fixture_dir)]),
            ("host-linux", [self.channel, "bench", address, str(fixture_dir)], [self.channel, "rejections", address, str(fixture_dir)]),
            ("linux-linux", client("ll-bench", "bench", f"{server_name}:38443"), client("ll-negative", "rejections", f"{server_name}:38443")),
            ("linux-host", client("lh-bench", "bench", f"host.docker.internal:{port}"), client("lh-negative", "rejections", f"host.docker.internal:{port}")),
        ]
        for name, benchmark, negative in paths:
            self.record_json(name, benchmark)
            self.results["acceptance"][name + "-negative"] = json.loads(self.command(name + "-negative", negative))
        relay = Relay(("127.0.0.1", port))
        try:
            self.command("relay-confidentiality", [self.channel, "probe", relay.address, str(fixture_dir)])
        finally:
            relay.close()
        assert relay.bytes > 1024 and not relay.plaintext_found and not relay.errors
        self.results["acceptance"]["relay-confidentiality"] = {"captured_bytes": relay.bytes, "canary_found": relay.plaintext_found, "scope": "smoke test, not cryptographic proof"}
        relay = Relay(("127.0.0.1", port), mutate=True)
        try:
            self.command("relay-active-tamper", [self.channel, "probe", relay.address, str(fixture_dir)], expected=1)
        finally:
            relay.close()
        assert relay.mutated
        assert "association failed: HandshakeFailed" in (self.logs / "relay-active-tamper.log").read_text()
        self.results["acceptance"]["relay-active-tamper"] = {"mutated": True, "authenticated_echo_refused": True}
        self.command("linux-server-logs", ["docker", "logs", server_name])

    def save(self):
        self.results["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (self.directory / "results.json").write_text(json.dumps(self.results, indent=2, ensure_ascii=False) + "\n")
        print(f"RESULTS: {self.directory / 'results.json'}", flush=True)

    def cleanup(self):
        for process, log in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            log.close()
        for name in reversed(self.containers):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        if self.network:
            subprocess.run(["docker", "network", "rm", self.network], capture_output=True, timeout=20)
        shutil.rmtree(self.directory / "fixtures", ignore_errors=True)

    def execute(self):
        try:
            self.environment()
            self.prepare()
            self.checks()
            # Benchmarks run serially after all compilation and conformance checks.
            self.storage_tests()
            self.container_crashes()
            self.network_tests()
            for name, digest in self.results["source_sha256"].items():
                if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                    raise RuntimeError(f"source changed during acceptance: {name}")
            self.results["source_unchanged"] = True
            self.results["run_status"] = "completed"
            # This profile has explicit machine-checkable lab criteria, kept
            # separate from the security/platform release manifest.
            from l001_local_gate import validate
            checks = validate(self.results)
            self.results["local_acceptance"] = {"profile": "L-001-local-docker-v1", "state": "passed", "checks": checks}
        except Exception as error:
            self.results["run_status"] = "failed"
            self.results["error"] = str(error)
            raise
        finally:
            self.cleanup()
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builder-container", help="Reuse an explicitly prepared disposable laboratory container")
    parser.add_argument("--skip-build", action="store_true", help="Deprecated compatibility option; incremental Cargo builds always verify source freshness")
    args = parser.parse_args()
    Lab(args).execute()


if __name__ == "__main__":
    main()
