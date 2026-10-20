#!/usr/bin/env python3
"""L-002 reproducible lab acceptance. Public fixture keys, never release signoff."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import time

from l001_local_docker import Relay
import l001_local_docker

ROOT = Path(__file__).resolve().parent.parent
CONTENT = b"LOOM-L002-PRIVATE-FILE-CANARY\nowner approved snapshot\n"
l001_local_docker.CANARY = CONTENT[:26]


class Lab:
    def __init__(self, output, binary=None):
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        (self.output / "logs").mkdir()
        self.binary = binary or ROOT / "target/debug/examples/l002_lan_lab"
        self.counter = 0
        self.owned_containers = []
        self.network = None
        self.processes = []
        self.events = []
        self.relays = []
        self.result = {"schema": 1, "profile": "L-002-isolated-lab-v1", "release_state": "blocked",
                       "checks": {}, "cases": {}, "started_utc": datetime.now(timezone.utc).isoformat()}

    def command(self, name, args, timeout=600, expected=0):
        print(name, flush=True)
        start = time.monotonic()
        p = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        log = self.output / "logs" / f"{name}.log"
        log.write_text(p.stdout + "\nSTDERR:\n" + p.stderr)
        self.result["checks"][name] = {"exit_code": p.returncode, "expected": expected,
                                         "elapsed_s": round(time.monotonic() - start, 3), "log": f"logs/{name}.log",
                                         "sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        if p.returncode != expected:
            raise RuntimeError(f"{name}: {p.returncode}: {p.stderr[-2000:]}")
        return p.stdout

    def line(self, process, seconds=15):
        if not select.select([process.stdout], [], [], seconds)[0]:
            raise RuntimeError("child output timeout")
        value = process.stdout.readline()
        if not value:
            raise RuntimeError(f"child exited: {process.poll()}")
        decoded = json.loads(value)
        self.events.append({"pid": process.pid, "event": decoded})
        return decoded

    def spawn(self, args):
        process = subprocess.Popen([str(a) for a in args], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, bufsize=1)
        self.processes.append(process)
        return process

    def finish(self, process, label, expected=0):
        if process.stdin:
            process.stdin.close()
            process.stdin = None
        out, err = process.communicate(timeout=20)
        (self.output / "logs" / f"{label}.log").write_text(out + "\nSTDERR:\n" + err)
        assert process.returncode == expected, (label, process.returncode, err)

    def request(self, client, command, ok=True):
        client.stdin.write(command + "\n")
        client.stdin.flush()
        reply = self.line(client)
        assert reply["ok"] == ok, (command, reply)
        return bytes.fromhex(reply["bytes_hex"])

    def host(self, mode, directory, *args):
        self.counter += 1
        return self.command(f"host-{self.counter}-{mode}", [self.binary, mode, directory, *args])

    def pair(self, directory, prefix=None, relay=False):
        self.counter += 1
        if prefix:
            server = self.spawn(["docker", "exec", "-i", prefix[0], "/build/debug/examples/l002_lan_lab", "serve", directory, "0.0.0.0:0"])
        else:
            server = self.spawn([self.binary, "serve", directory])
        marker = self.line(server)
        address = marker["listen"]
        if prefix:
            address = prefix[2] + ":" + address.rsplit(":", 1)[1]
        proxy = None
        if relay:
            host, port = address.rsplit(":", 1)
            proxy = Relay((host, int(port)))
            self.relays.append(proxy)
            address = proxy.address
        if prefix:
            client = self.spawn(["docker", "exec", "-i", prefix[1], "/build/debug/examples/l002_lan_lab", "client", directory, address])
        else:
            client = self.spawn([self.binary, "client", directory, address])
        return server, client, proxy

    def close_pair(self, pair, label):
        server, client, relay = pair
        self.finish(client, f"{label}-client")
        self.finish(server, f"{label}-server")
        if relay:
            relay.close()
            assert relay.bytes > len(CONTENT) and not relay.plaintext_found
            self.result["cases"][f"{label}-encrypted-bearer"] = {"passed": True, "ciphertext_bytes": relay.bytes, "plaintext_found": False}

    def scenarios(self, directory, prefix=None):
        name = "linux-lan" if prefix else "host-tcp"
        def policy(mode):
            if prefix:
                self.command(f"{name}-{mode}-{self.counter}", ["docker", "exec", prefix[0], "/build/debug/examples/l002_lan_lab", mode, directory])
            else:
                self.host(mode, directory)
        policy("grant")
        pair = self.pair(directory, prefix, relay=not prefix)
        _, client, _ = pair
        self.request(client, "wrong-resource", False)
        self.request(client, "write", False)
        self.request(client, "open")
        self.request(client, "read 0", False)
        self.request(client, "read 4097", False)
        received = b""
        while True:
            chunk = self.request(client, "read 7")
            if not chunk:
                break
            received += chunk
        assert received == CONTENT
        self.close_pair(pair, f"{name}-full-read")
        self.result["cases"][f"{name}-exact-file-and-refusals"] = {"passed": True, "bytes": len(received), "refusals": 4}
        pair = self.pair(directory, prefix)
        _, client, _ = pair
        self.request(client, "open")
        assert self.request(client, "read 4") == CONTENT[:4]
        policy("revoke")
        start = time.monotonic()
        self.request(client, "read 4", False)
        self.request(client, "open", False)
        elapsed = time.monotonic() - start
        policy("grant")
        self.request(client, "read 4", False)
        self.request(client, "open")
        assert self.request(client, "read 4") == CONTENT[:4]
        policy("revoke")
        self.close_pair(pair, f"{name}-revocation")
        pair = self.pair(directory, prefix)
        self.request(pair[1], "open", False)
        self.close_pair(pair, f"{name}-restart-deny")
        self.result["cases"][f"{name}-revoke-regrant-restart"] = {"passed": True, "post_revoke_refusal_s": round(elapsed, 4)}

    def crashes(self):
        for operation in ["grant", "revoke"]:
            for cut, committed in [("before-insert", False), ("after-insert", False), ("after-commit", True)]:
                case = cut if operation == "grant" else f"revoke-{cut}"
                directory = self.output / f"crash-{case}"
                self.host("init", directory)
                baseline = 0
                if operation == "revoke":
                    self.host("grant", directory)
                    baseline = 1
                self.host("prepare", directory, operation)
                process = self.spawn([self.binary, "append", directory, "policy", cut])
                assert self.line(process) == {"cut": cut}
                process.kill()
                self.finish(process, f"kill-{case}", expected=-9)
                states = [json.loads(row) for row in self.host("status", directory).splitlines()]
                assert states[0]["sequence"] == baseline + int(committed), states
                if operation == "revoke":
                    assert states[0]["allowed"] == (not committed), states
                self.host("append", directory, "policy")
                self.host("append", directory, "policy")
                self.host("append", directory, "witness-a")
                pair = self.pair(directory)
                self.request(pair[1], "open", False)
                self.close_pair(pair, f"{case}-partial-quorum")
                self.host("append", directory, "witness-b")
                states = [json.loads(row) for row in self.host("status", directory).splitlines()]
                assert all(row["sequence"] == baseline + 1 for row in states)
                pair = self.pair(directory)
                self.request(pair[1], "open", operation == "grant")
                if operation == "grant":
                    assert self.request(pair[1], "read 4096") == CONTENT
                self.close_pair(pair, f"{case}-recovered")
                self.result["cases"][f"sigkill-{case}"] = {"passed": True, "committed_on_restart": committed, "idempotent_retry": True, "partial_quorum_refused": True}

    def docker(self):
        token = f"loom-l002-{os.getpid()}"
        builder = token + "-build"
        self.command("docker-builder", ["docker", "run", "-d", "--name", builder, "--cpus=4", "--memory=4g", "--pids-limit=512",
            "-v", f"{ROOT}:/workspace", "-v", "loom-l001-cargo:/usr/local/cargo/registry", "-v", "loom-l001-target:/build", "loom-l001-lab:local", "sleep", "infinity"])
        self.owned_containers.append(builder)
        self.result["linux_host"] = self.command("linux-host", ["docker", "exec", builder, "uname", "-a"]).strip()
        self.result["docker_image"] = self.command("docker-image", ["docker", "inspect", builder, "--format", "{{.Image}}"]).strip()
        for name, args in [("linux-tests", ["cargo", "test", "--workspace", "--all-targets", "--features", "loom-core/experimental-lan", "--locked"]),
                           ("linux-clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--features", "loom-core/experimental-lan", "--locked", "--", "-D", "warnings"]),
                           ("linux-build", ["cargo", "build", "-p", "loom-core", "--example", "l002_lan_lab", "--features", "experimental-lan", "--locked"])]:
            out = self.command(name, ["docker", "exec", builder, *args], timeout=1200)
            if name == "linux-tests": self.result["linux_tests_passed"] = self.test_count(out)
        runtime_dir = f"/build/{token}-runtime"
        self.command("linux-runtime-crashes", ["docker", "exec", "-e", f"LOOM_L002_BASE_COMMIT={self.result['base_commit']}", builder, "python3", "scripts/l002_acceptance.py",
            "--host-only", "--runtime-only", "--binary", "/build/debug/examples/l002_lan_lab", "--output", runtime_dir])
        native = self.output / "linux-runtime"
        native.mkdir()
        for name in ["summary.json", "events.json", "logs"]:
            self.command("linux-evidence-" + name.replace(".", "-"), ["docker", "cp", f"{builder}:{runtime_dir}/{name}", native / name])
        runtime = json.loads((native / "summary.json").read_text())
        assert runtime["state"] == "host-only-passed"
        self.result["linux_runtime"] = {"evidence": "linux-runtime/summary.json", "sha256": hashlib.sha256((native / "summary.json").read_bytes()).hexdigest(),
                                        "cases": runtime["cases"]}
        self.network = token + "-isolated"
        self.command("isolated-network", ["docker", "network", "create", "--internal", self.network])
        peers = []
        for role in ["server", "client"]:
            container = token + "-" + role
            self.command("peer-" + role, ["docker", "run", "-d", "--name", container, "--network", self.network, "--cpus=1", "--memory=256m", "--pids-limit=64",
                "-e", "LOOM_L002_ISOLATED_LAB=1", "-v", "loom-l001-target:/build:ro", "-v", f"{self.output}:/lab", "loom-l001-lab:local", "sleep", "infinity"])
            self.owned_containers.append(container)
            peers.append(container)
        network = json.loads(self.command("server-network", ["docker", "inspect", peers[0], "--format", "{{json .NetworkSettings.Networks}} "]))
        address = network[self.network]["IPAddress"]
        self.command("linux-init", ["docker", "exec", peers[0], "/build/debug/examples/l002_lan_lab", "init", "/lab/linux-fixture"])
        prefix = (*peers, address)
        self.scenarios("/lab/linux-fixture", prefix)
        self.command("server-container-kill", ["docker", "kill", "--signal", "KILL", peers[0]])
        self.command("server-container-restart", ["docker", "start", peers[0]])
        pair = self.pair("/lab/linux-fixture", prefix)
        self.request(pair[1], "open", False)
        self.close_pair(pair, "linux-container-restart-deny")
        self.result["cases"]["linux-container-sigkill-restart"] = {"passed": True, "grant_resurrected": False}

    @staticmethod
    def test_count(output):
        rows = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", output)
        assert rows and all(row[1:] == ("0", "0") for row in rows)
        return sum(int(row[0]) for row in rows)

    def run(self, docker=True, runtime_only=False):
        try:
            if shutil.which("git"):
                self.result["base_commit"] = self.command("base-commit", ["git", "rev-parse", "HEAD"]).strip()
                self.command("source-diff", ["git", "diff", "--binary", "HEAD", "--", "Cargo.toml", "Cargo.lock", "crates", "apps", "scripts", ".github"])
            else:
                self.result["base_commit"] = os.environ["LOOM_L002_BASE_COMMIT"]
            self.result["host"] = self.command("host", ["uname", "-a"]).strip()
            self.result["rust"] = self.command("rust-version", ["rustc", "--version"]).strip()
            if not runtime_only:
                self.command("format", ["cargo", "fmt", "--all", "--", "--check"])
                out = self.command("host-tests", ["cargo", "test", "--workspace", "--all-targets", "--features", "loom-core/experimental-lan", "--locked"])
                self.result["host_tests_passed"] = self.test_count(out)
                self.command("host-clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--features", "loom-core/experimental-lan", "--locked", "--", "-D", "warnings"])
                self.command("host-build", ["cargo", "build", "-p", "loom-core", "--example", "l002_lan_lab", "--features", "experimental-lan", "--locked"])
            self.crashes()
            directory = self.output / "host-fixture"
            self.host("init", directory)
            self.scenarios(directory)
            if docker: self.docker()
            # Source hashes cover new/untracked implementation too. Never copy
            # runtime fixtures, certificates or private key files into evidence.
            if shutil.which("git"):
                paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
            else:
                paths = [str(p.relative_to(ROOT)) for folder in ["crates", "apps", "scripts"] for p in (ROOT / folder).rglob("*") if p.is_file() and "target" not in p.parts]
                paths += ["Cargo.toml", "Cargo.lock", ".github/workflows/rust.yml"]
            self.result["source_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths
                if (name.startswith(("crates/", "apps/", "scripts/")) or name in ["Cargo.toml", "Cargo.lock", ".github/workflows/rust.yml"])
                and (ROOT / name).is_file() and not name.endswith(".pyc")}
            self.result["state"] = "passed" if docker else "host-only-passed"
        except BaseException as error:
            self.result["state"] = "failed"
            self.result["error"] = str(error)
            raise
        finally:
            for process in self.processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            for relay in self.relays:
                relay.close()
            for container in reversed(self.owned_containers):
                self.command("cleanup-" + container, ["docker", "rm", "-f", container])
            if self.network:
                self.command("cleanup-network", ["docker", "network", "rm", self.network])
            self.result["finished_utc"] = datetime.now(timezone.utc).isoformat()
            events_path = self.output / "events.json"
            events_path.write_text(json.dumps(self.events, indent=2) + "\n")
            self.result["events"] = {"path": "events.json", "sha256": hashlib.sha256(events_path.read_bytes()).hexdigest()}
            (self.output / "summary.json").write_text(json.dumps(self.result, indent=2) + "\n")
        print(self.output / "summary.json", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target" / ("l002-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--runtime-only", action="store_true")
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args()
    Lab(arguments.output, arguments.binary).run(docker=not arguments.host_only, runtime_only=arguments.runtime_only)
