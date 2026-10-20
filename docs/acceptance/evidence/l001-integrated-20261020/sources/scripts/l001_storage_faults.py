#!/usr/bin/env python3
"""Disposable signed-journal SIGKILL, tamper and backup-restore experiments."""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import time


def run(binary, mode, path, count=None, success=True):
    command = [binary, mode, str(path)]
    if count is not None:
        command.append(str(count))
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if success:
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)
    if result.returncode == 0:
        raise AssertionError("tampered journal was accepted")
    return {"rejected": True, "exit_code": result.returncode, "stderr": result.stderr.strip()}


def backup(source, destination):
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    trials = []
    for index, acknowledged_floor in enumerate([10, 25, 50]):
        path = args.directory / f"kill-{index}.sqlite"
        with (args.directory / f"kill-{index}.stderr").open("w") as log:
            child = subprocess.Popen([args.binary, "writer", str(path)], stdout=subprocess.PIPE, stderr=log, bufsize=0)
            acknowledged = 0
            deadline = time.monotonic() + 30
            try:
                while acknowledged < acknowledged_floor:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([child.stdout], [], [], max(0, remaining))[0]:
                        raise TimeoutError("writer failed to acknowledge test prefix")
                    line = child.stdout.readline()
                    if not line:
                        raise RuntimeError("writer exited before forced kill")
                    if line.startswith(b"ACK "):
                        acknowledged = int(line.split()[1])
                os.kill(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
                child.stdout.close()
        recovered = run(args.binary, "inspect", path)
        assert recovered["sequence"] >= acknowledged
        assert recovered["pending"] == recovered["sequence"]
        assert recovered["admission_paused"]
        with sqlite3.connect(path) as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        trials.append({"acknowledged_floor": acknowledged, "recovered": recovered, "signal": "SIGKILL", "integrity_check": "ok"})

    baseline = args.directory / "baseline.sqlite"
    run(args.binary, "fill", baseline, 5)
    signed_copy = args.directory / "old-backup.sqlite"
    backup(baseline, signed_copy)
    run(args.binary, "fill", baseline, 3)
    assert run(args.binary, "inspect", baseline)["sequence"] == 8
    backup(signed_copy, baseline)
    rolled_back = run(args.binary, "inspect", baseline)
    assert rolled_back["sequence"] == 5 and rolled_back["admission_paused"]

    tampered = args.directory / "signature-tamper.sqlite"
    backup(signed_copy, tampered)
    with sqlite3.connect(tampered) as db:
        db.execute("UPDATE unified_policy_events SET evidence=zeroblob(length(evidence)) WHERE seq=1")
    signature = run(args.binary, "inspect", tampered, success=False)
    mirror = args.directory / "missing-outbox.sqlite"
    backup(signed_copy, mirror)
    with sqlite3.connect(mirror) as db:
        db.execute("DELETE FROM unified_policy_outbox WHERE seq=1")
    missing_mirror = run(args.binary, "inspect", mirror, success=False)
    print(json.dumps({
        "sigkill_restart_trials": trials,
        "signature_tamper": signature,
        "missing_outbox": missing_mirror,
        "restored_valid_old_backup": rolled_back,
        "independent_rollback_detection_available": False,
        "physical_power_loss_tested": False,
    }))


if __name__ == "__main__":
    main()
