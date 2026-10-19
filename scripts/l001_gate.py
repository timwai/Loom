#!/usr/bin/env python3
"""Fail-closed L-001 milestone status verifier, never an automatic safety cert."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "acceptance" / "l001.json"
REQUIRED = {
    "E2EE-01", "TLS-ID-01", "WIRE-01",
    "AUTHZ-RACE-01", "AUTHZ-CRASH-02", "ROLLBACK-01",
    "PLATFORM-ANDROID-01", "PLATFORM-WIN-01", "PLATFORM-MAC-01",
}
SIGNOFFS = {"security", "hardware", "interop", "platform"}
STATES = {"blocked", "partial", "passed"}


def validate() -> tuple[bool, list[str]]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["milestone"] == "L-001", "wrong milestone"
    engineering = data.get("engineering", {})
    if engineering:
        assert engineering.get("status") in {"pending", "complete"}, "invalid engineering state"
        if engineering["status"] == "complete":
            main_sha = engineering.get("integrated_main_commit", "")
            assert isinstance(main_sha, str) and len(main_sha) == 40
            assert all(c in "0123456789abcdef" for c in main_sha), "invalid integration SHA"
            assert engineering.get("scope"), "missing engineering-only scope"
    checks = data["checks"]
    ids = [item["id"] for item in checks]
    assert set(ids) == REQUIRED and len(ids) == len(REQUIRED), "gate set incomplete"
    assert all(item["state"] in STATES for item in checks), "invalid gate state"
    assert all(item["phase"] in {"L-001A", "L-001B", "L-001C", "L-001D"}
               for item in checks), "unknown phase"
    pending = [item["id"] for item in checks if item["state"] != "passed"]
    approvals = data["signoffs"]
    assert set(approvals) == SIGNOFFS, "missing review domain"
    for key, reference in approvals.items():
        if reference is not None:
            assert isinstance(reference, str) and reference.startswith(
                "docs/acceptance/evidence/"
            ), f"{key} has non-repository reference"
            evidence = (ROOT / reference).resolve()
            assert evidence.is_relative_to(ROOT.resolve()), "unsafe evidence path"
            assert evidence.is_file(), f"missing approval evidence: {reference}"
        else:
            pending.append("SIGNOFF:" + key)
    fully_attested = not pending
    assert data["state"] in {"blocked", "complete"}, "invalid milestone status"
    if data["state"] == "complete":
        assert fully_attested, "FORBIDDEN: milestone claimed complete with missing gates"
    if fully_attested:
        assert data["state"] == "complete", "all gates approved but completion not reviewed"
    return fully_attested, pending


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--require-complete", action="store_true")
    args = p.parse_args()
    try:
        complete, pending = validate()
    except (KeyError, ValueError, AssertionError, OSError) as exc:
        print(f"L-001 INVALID ACCEPTANCE MANIFEST: {exc}", file=sys.stderr)
        return 2
    print("L-001 COMPLETION: " + ("COMPLETE" if complete else "BLOCKED"))
    if pending:
        print("Unmet gates: " + ", ".join(pending))
    if args.require_complete and not complete:
        print("Refusing release: all L-001A/B/C/D reviews required", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
