#!/usr/bin/env python3
"""Separate-process, separate-SQLite fresh Witness recovery laboratory.

Public fixture keys and same-host files are not independent trusted storage.
No service enrollment, production Witness writer or admission is exercised.
"""
import argparse
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess


def backup(source, destination):
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)


class Experiment:
    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = directory
        self.commands = []
        self.checks = {}

    def run(self, *args, error=None):
        command = [self.binary, *map(str, args)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.commands.append({"argv": command, "exit_code": result.returncode})
        if error is not None:
            if result.returncode != 1 or error not in result.stderr:
                raise AssertionError(f"expected {error}: {result.returncode} {result.stderr}")
            return {"rejected": True, "reason": error, "exit_code": result.returncode}
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def replies(self, nonce):
        return [self.run("witness-read", path, seed, nonce)
                for path, seed in zip(self.witnesses, [21, 22])]

    def recover(self, nonce, replies, error=None):
        return self.run("recover", self.local, nonce,
                        *[r["receipt"] for r in replies], error=error)

    def execute(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        self.local = self.directory / "peer.sqlite"
        self.witnesses = [self.directory / f"witness-{i}.sqlite" for i in [1, 2]]
        old = self.directory / "old-signed-backup.sqlite"
        self.run("fill", self.local, 5)
        backup(self.local, old)
        for path in self.witnesses:
            backup(self.local, path)
        old_nonce = secrets.token_hex(32)
        old_replies = self.replies(old_nonce)
        # Fixture-only provisioning/advance: each process replays its own full
        # Owner-signed history; there is no remotely writable Witness endpoint.
        for path in [self.local, *self.witnesses]:
            self.run("fill", path, 3)
        current = self.directory / "current-signed-backup.sqlite"
        backup(self.local, current)
        nonce = secrets.token_hex(32)
        replies = self.replies(nonce)
        assert all(r["sequence"] == 8 for r in replies)
        assert replies[0]["pid"] != replies[1]["pid"]
        healthy = self.recover(nonce, replies)
        assert healthy["sequence"] == 8 and healthy["admission_paused"]
        self.checks["current_signed_history"] = healthy

        backup(old, self.local)
        assert self.run("inspect", self.local)["sequence"] == 5
        nonce = secrets.token_hex(32)
        replies = self.replies(nonce)
        self.checks["valid_old_local_backup"] = self.recover(
            nonce, replies, error="LocalRollbackOrFork")
        self.checks["old_signed_response_new_nonce"] = self.recover(
            nonce, old_replies, error="WrongChallenge")
        self.checks["one_witness_offline"] = self.recover(
            nonce, replies[:1], error="MissingOrDuplicateWitness")
        backup(current, self.local)
        forged = [dict(r) for r in replies]
        receipt = bytearray.fromhex(forged[0]["receipt"])
        receipt[-1] ^= 1
        forged[0]["receipt"] = receipt.hex()
        self.checks["forged_signature"] = self.recover(
            nonce, forged, error="InvalidSignature")

        backup(old, self.witnesses[1])
        nonce = secrets.token_hex(32)
        self.checks["split_witness_histories"] = self.recover(
            nonce, self.replies(nonce), error="SplitWitnesses")
        backup(current, self.witnesses[1])

        for case, sql in [
            ("local_signed_evidence_tamper", "UPDATE unified_policy_events SET evidence=zeroblob(length(evidence)) WHERE seq=1"),
            ("local_missing_outbox", "DELETE FROM unified_policy_outbox WHERE seq=1"),
        ]:
            with sqlite3.connect(self.local) as db:
                db.execute(sql)
            self.checks[case] = self.recover(nonce, replies, error="inspect: Conflict")
            backup(current, self.local)

        with sqlite3.connect(self.witnesses[0]) as db:
            db.execute("DELETE FROM unified_policy_outbox WHERE seq=1")
        self.checks["corrupt_witness_refuses_to_sign"] = self.run(
            "witness-read", self.witnesses[0], 21, secrets.token_hex(32), error="inspect: Conflict")
        backup(current, self.witnesses[0])

        nonce = secrets.token_hex(32)
        healed = self.recover(nonce, self.replies(nonce))
        assert healed["sequence"] == 8 and healed["admission_paused"]
        self.checks["fresh_recheck_after_repair"] = healed

        # Explicit counterexample: restoring ALL same-host storage domains can
        # still roll back this lab. Never classify these files as trusted media.
        for path in [self.local, *self.witnesses]:
            backup(old, path)
        nonce = secrets.token_hex(32)
        boundary = self.recover(nonce, self.replies(nonce))
        assert boundary["sequence"] == 5 and boundary["admission_paused"]
        return {
            "status": "passed", "checks": self.checks,
            "commands": self.commands,
            "all_same_host_stores_rollback_counterexample": boundary,
            "independent_storage_certified": False,
            "production_admission_enabled": False,
            "fixture_keys_only": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(Experiment(args.binary, args.directory).execute()))


if __name__ == "__main__":
    main()
