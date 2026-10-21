#!/usr/bin/env python3
"""Reproduce the L-002 whole-installation rollback boundary on private fixtures.

Run from the repository with --output target/<fresh-directory>. This probe uses
only loopback TCP/TLS, public laboratory keys and newly enrolled disposable logs.
Exit 1 means the formal antirollback requirement failed, not a passing test.
The output includes no private keys, certificates or SQLite images; disposable
fixture state is deleted even on failure. Requires a built l002_lan_lab example.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
from l002_acceptance import CONTENT, Lab  # noqa: E402

LOGS = ("policy", "witness-a", "witness-b")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/examples/l002_lan_lab")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or output.is_relative_to(ROOT / "docs"):
        parser.error("runtime output must be a fresh disposable directory outside docs/")
    lab = Lab(output, args.binary.resolve())
    fixture = output / "private-runtime"
    baseline = output / "private-baseline"
    revoked = output / "private-revoked"
    result = {
        "schema": 1,
        "profile": "L-002-formal-rollback-probe-v1",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "cases": {},
        "release_state": "blocked",
    }

    def states():
        return [json.loads(row) for row in lab.host("status", fixture).splitlines()]

    def copy_logs(destination, source):
        destination.mkdir(exist_ok=True)
        for name in LOGS:
            shutil.copy2(source / f"{name}.sqlite", destination / f"{name}.sqlite")

    def check(case, expected_allow):
        pair = lab.pair(fixture)
        try:
            reply = lab.request(pair[1], "open", ok=expected_allow)
            assert reply == b""
            data = lab.request(pair[1], "read 4096") if expected_allow else b""
            if expected_allow:
                assert data == CONTENT
            result["cases"][case] = {
                "status": "passed", "observed_allow": expected_allow,
                "bytes_received": len(data),
            }
        finally:
            lab.close_pair(pair, case)

    exit_code = 2
    try:
        lab.command("host", ["uname", "-sm"])
        lab.host("init", fixture)
        lab.host("grant", fixture)
        assert all(s["sequence"] == 1 and s["allowed"] for s in states())
        copy_logs(baseline, fixture)
        check("control-granted-read", True)

        lab.host("revoke", fixture)
        assert all(s["sequence"] == 2 and not s["allowed"] for s in states())
        copy_logs(revoked, fixture)
        check("control-committed-revoke-restart", False)

        shutil.copy2(baseline / "policy.sqlite", fixture / "policy.sqlite")
        result["policy_only_restore"] = states()
        check("control-policy-only-restore", False)

        copy_logs(fixture, revoked)
        shutil.copy2(baseline / "witness-a.sqlite", fixture / "witness-a.sqlite")
        result["one_witness_restore"] = states()
        check("control-one-witness-restore", False)

        # No process is running and every connection is closed at each copy.
        # Restore only the three signed logs, without changing clocks, keys,
        # certificates or requesting any new grant or replacement signature.
        copy_logs(fixture, baseline)
        result["whole_installation_restore"] = states()
        pair = lab.pair(fixture)
        try:
            client = pair[1]
            client.stdin.write("open\n")
            client.stdin.flush()
            reply = lab.line(client)
            assert isinstance(reply.get("ok"), bool)
            observed_allow = reply["ok"]
            data = lab.request(client, "read 4096") if observed_allow else b""
            if observed_allow:
                assert data == CONTENT
            result["cases"]["FORMAL-ROLLBACK-ALL"] = {
                "requirement": "A committed revocation must survive backup restore of the installation.",
                "expected_allow": False,
                "observed_allow": observed_allow,
                "bytes_received": len(data),
                "content_sha256": hashlib.sha256(data).hexdigest() if data else None,
                "status": "failed" if observed_allow else "passed",
                "fresh_challenge": "The unmodified candidate generates new OS-CSPRNG nonces for open and read.",
            }
        finally:
            lab.close_pair(pair, "whole-installation-restore")
        result["state"] = "failed" if observed_allow else "passed"
        exit_code = 1 if observed_allow else 0
    except Exception as error:
        result["state"] = "error"
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        for process in lab.processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        for directory in (fixture, baseline, revoked):
            shutil.rmtree(directory, ignore_errors=True)
        events = output / "events.json"
        events.write_text(json.dumps(lab.events, indent=2) + "\n")
        result["events"] = {"path": "events.json", "sha256": hashlib.sha256(events.read_bytes()).hexdigest()}
        result["checks"] = lab.result["checks"]
        # Process-exit logs are also part of the archived transcript.
        result["log_sha256"] = {
            str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((output / "logs").glob("*.log"))
        }
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"FORMAL ROLLBACK: {result['state'].upper()} (exit {exit_code})", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
