#!/usr/bin/env python3
"""Validate reproducible L-002 lab evidence without granting release approval."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_CASES = {
    "sigkill-before-insert", "sigkill-after-insert", "sigkill-after-commit",
    "sigkill-revoke-before-insert", "sigkill-revoke-after-insert", "sigkill-revoke-after-commit",
    "host-tcp-full-read-encrypted-bearer", "host-tcp-exact-file-and-refusals",
    "host-tcp-revoke-regrant-restart", "linux-lan-exact-file-and-refusals",
    "linux-lan-revoke-regrant-restart", "linux-container-sigkill-restart",
}
REQUIRED_CHECKS = {"format", "host-tests", "host-clippy", "host-build", "linux-tests", "linux-clippy", "linux-build"}
REQUIRED_BLOCKERS = {"independent-witnesses", "production-admission", "independent-review", "physical-platforms"}


def checked_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError(f"invalid evidence path: {value}")
    return path


def validate(require_lab=False, require_release=False):
    manifest = json.loads((ROOT / "docs/acceptance/l002.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("milestone") != "L-002":
        raise ValueError("invalid L-002 manifest")
    lab = manifest["laboratory"]
    if lab["profile"] != "L-002-isolated-lab-v1":
        raise ValueError("unknown lab profile")
    if manifest["release"]["status"] != "blocked" or set(manifest["release"]["blockers"]) != REQUIRED_BLOCKERS:
        raise ValueError("release requires separate reviewed gate changes; lab results cannot promote it")
    if lab["status"] == "passed":
        evidence = checked_path(lab["evidence"])
        if hashlib.sha256(evidence.read_bytes()).hexdigest() != lab["sha256"]:
            raise ValueError("evidence checksum mismatch")
        result = json.loads(evidence.read_text())
        if result["state"] != "passed" or result["profile"] != lab["profile"] or result["release_state"] != "blocked":
            raise ValueError("incomplete lab or unsupported release claim")
        for key in REQUIRED_CASES:
            if result["cases"].get(key, {}).get("passed") is not True:
                raise ValueError(f"missing lab case: {key}")
        for key, record in result["checks"].items():
            if record["exit_code"] != 0 or record["expected"] != 0:
                raise ValueError(f"failed lab command: {key}")
            log = checked_path(str(evidence.parent.relative_to(ROOT) / record["log"]))
            if hashlib.sha256(log.read_bytes()).hexdigest() != record["sha256"]:
                raise ValueError(f"changed evidence log: {key}")
        if not REQUIRED_CHECKS.issubset(result["checks"]):
            raise ValueError("missing required validation commands")
        events = checked_path(str(evidence.parent.relative_to(ROOT) / result["events"]["path"]))
        if hashlib.sha256(events.read_bytes()).hexdigest() != result["events"]["sha256"]:
            raise ValueError("runtime transcript changed")
        native = checked_path(str(evidence.parent.relative_to(ROOT) / result["linux_runtime"]["evidence"]))
        if hashlib.sha256(native.read_bytes()).hexdigest() != result["linux_runtime"]["sha256"]:
            raise ValueError("Linux runtime evidence changed")
        runtime = json.loads(native.read_text())
        for key in REQUIRED_CASES:
            if not key.startswith("sigkill-"):
                continue
            if runtime["cases"].get(key, {}).get("passed") is not True:
                raise ValueError(f"missing Linux crash case: {key}")
        for key, record in runtime["checks"].items():
            path = checked_path(str(native.parent.relative_to(ROOT) / record["log"]))
            if record["exit_code"] != record["expected"] or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                raise ValueError(f"invalid Linux runtime log: {key}")
        native_events = checked_path(str(native.parent.relative_to(ROOT) / runtime["events"]["path"]))
        if hashlib.sha256(native_events.read_bytes()).hexdigest() != runtime["events"]["sha256"]:
            raise ValueError("Linux runtime transcript changed")
        if result["host_tests_passed"] != lab["tests_per_os"] or result["linux_tests_passed"] != lab["tests_per_os"]:
            raise ValueError("test counts disagree")
        for path, expected in result["source_sha256"].items():
            if hashlib.sha256(checked_path(path).read_bytes()).hexdigest() != expected:
                raise ValueError(f"source changed since acceptance: {path}; rerun scripts/l002_acceptance.py")
        inventory = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
        current = {name for name in inventory if (name.startswith(("crates/", "apps/", "scripts/")) or name in ["Cargo.toml", "Cargo.lock", ".github/workflows/rust.yml"])
                   and (ROOT / name).is_file() and not name.endswith(".pyc")}
        if current != set(result["source_sha256"]):
            raise ValueError("source inventory changed since acceptance")
        if not result["source_sha256"] or "crates/loom-core/src/lan_read.rs" not in result["source_sha256"]:
            raise ValueError("missing source identity")
    elif require_lab:
        raise ValueError("L-002 lab acceptance incomplete")
    print(f"L-002 LAB: {lab['status'].upper()} ({lab['profile']})")
    print("L-002 RELEASE: BLOCKED — " + ", ".join(manifest["release"]["blockers"]))
    if require_release:
        subprocess.run([sys.executable, str(ROOT / "scripts/l001_gate.py"), "--require-complete"], check=False)
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-lab", action="store_true")
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    try:
        sys.exit(validate(args.require_lab, args.require_release))
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"L-002 evidence invalid: {error}", file=sys.stderr)
        sys.exit(1)
