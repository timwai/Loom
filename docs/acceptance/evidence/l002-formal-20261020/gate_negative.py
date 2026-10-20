#!/usr/bin/env python3
"""Run isolated formal-evidence tamper probes; print JSON, never edit the archive.

Run from the repository root after the archived manifest has been finalized.
The current campaign is intentionally FAILED, so both evidence validation (0)
and formal acceptance refusal (1) are verified. Only temporary copies mutate.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile

root = Path.cwd()
spec = importlib.util.spec_from_file_location("l002_gate", root / "scripts/l002_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
original = json.loads((root / "docs/acceptance/l002.json").read_text())
evidence_path = Path(original["formal_acceptance"]["evidence"])
checks = []


def check(name, mutate=None, expected_error=None, require_formal=False, expected_exit=0):
    with tempfile.TemporaryDirectory(prefix="loom-formal-gate-") as temp:
        temp_root = Path(temp).resolve()
        folder = temp_root / evidence_path.parent
        shutil.copytree(root / evidence_path.parent, folder)
        manifest = copy.deepcopy(original)
        if mutate:
            mutate(manifest, folder)
        gate.ROOT = temp_root
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                code = gate.validate_formal(manifest, require_formal)
            assert expected_error is None, f"{name}: mutation accepted"
            assert code == expected_exit, (name, code)
            checks.append({"name": name, "passed": True, "exit_code": code})
        except ValueError as error:
            assert expected_error and expected_error in str(error), (name, str(error))
            checks.append({"name": name, "passed": True, "rejection": str(error)})


def rewrite_summary(manifest, folder, transform):
    path = folder / "summary.json"
    result = json.loads(path.read_text())
    transform(result)
    path.write_text(json.dumps(result, indent=2) + "\n")
    manifest["formal_acceptance"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()


check("valid-failed-record-is-consistent")
check("valid-failed-record-refuses-formal-pass", require_formal=True, expected_exit=1)
check("manifest-only-promotion", lambda m, f: m["formal_acceptance"].update(status="passed"),
      "claim disagrees")
check("log-tamper", lambda m, f: (f / "preflight/default-daemon.log").write_text("tampered\n"),
      "formal artifact changed")
check("unrecorded-artifact", lambda m, f: (f / "injected.log").write_text("injected\n"),
      "inventory changed")


def promote_all(manifest, folder):
    manifest["formal_acceptance"]["status"] = "passed"
    def promote(result):
        result["state"] = "passed"
        for requirement in result["requirements"].values():
            requirement["status"] = "passed"
    rewrite_summary(manifest, folder, promote)


check("rehashed-all-green-claim-still-refuses-observed-allow", promote_all,
      "rollback requirement disagrees")


def forge_probe_success(manifest, folder):
    path = folder / "rollback-host/summary.json"
    probe = json.loads(path.read_text())
    probe["state"] = "passed"
    probe["cases"]["FORMAL-ROLLBACK-ALL"]["status"] = "passed"
    path.write_text(json.dumps(probe, indent=2) + "\n")
    rewrite_summary(manifest, folder, lambda r: r["artifact_sha256"].update({
        "rollback-host/summary.json": hashlib.sha256(path.read_bytes()).hexdigest(),
    }))


check("rehashed-probe-success-still-refuses-observed-allow", forge_probe_success,
      "probe status disagrees")


def forge_denial(manifest, folder):
    path = folder / "rollback-host/summary.json"
    probe = json.loads(path.read_text())
    probe["state"] = "passed"
    probe["cases"]["FORMAL-ROLLBACK-ALL"].update(
        status="passed", observed_allow=False, bytes_received=0, content_sha256=None)
    path.write_text(json.dumps(probe, indent=2) + "\n")
    rewrite_summary(manifest, folder, lambda r: r["artifact_sha256"].update({
        "rollback-host/summary.json": hashlib.sha256(path.read_bytes()).hexdigest(),
    }))


check("rehashed-false-denial-still-refuses-successful-TLS-transcript", forge_denial,
      "claim disagrees with TLS transcript")
check("wrong-profile", lambda m, f: m["formal_acceptance"].update(profile="unreviewed"),
      "wrong formal acceptance profile")
check("missing-formal-record", lambda m, f: m.pop("formal_acceptance"),
      "has not been executed", require_formal=True)
print(json.dumps({"state": "passed", "scope": "Consistency/refusal tests, not independent security signoff.",
                  "checks": checks}, indent=2))
