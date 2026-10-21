#!/usr/bin/env python3
"""Validate the bounded L-001 host/Docker lab profile, never release gates."""
import argparse
import json
import math
from pathlib import Path

PROFILE = "L-001-local-docker-v1"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def validate(result):
    checks = []
    require(result.get("run_status") == "completed", "experiment did not complete")
    require(result.get("source_unchanged") is True and result.get("source_sha256"), "source freshness unverified")
    checks.append("SOURCE: source hashes unchanged; native/Linux rebuilt")
    commands = result["commands"]
    expected = {
        "host-release-build": 0, "linux-release-build": 0,
        "host-tests": 0, "linux-tests": 0, "host-format": 0,
        "host-clippy": 0, "linux-clippy": 0, "linux-doc": 0,
        "acceptance-manifest": 0, "release-still-refused": 1,
        "wire-kotlin-compile": 0, "wire-kotlin": 0,
    }
    for environment in ["host", "linux"]:
        for suffix in ["wire-go", "wire-js", "signature-go", "signature-js", "bootstrap"]:
            expected[f"{environment}-{suffix}"] = 0
        expected[f"{environment}-tpm-refused"] = 2
    for name, exit_code in expected.items():
        require(commands.get(name, {}).get("exit_code") == exit_code, f"missing or failed command: {name}")
    require(all(c["exit_code"] == c["expected_exit_code"] for c in commands.values()), "unexpected command result")
    checks.extend(["BUILD: native/Linux tests, format, strict Clippy, Linux docs",
                   "WIRE: Rust/Go/JavaScript/Kotlin vectors",
                   "FAIL-CLOSED: bootstrap disabled; missing TPM and release refused"])
    acceptance = result["acceptance"]
    for environment in ["host", "linux"]:
        tests = acceptance[f"{environment}-tests"]
        require(tests["passed"] >= 248 and tests["failed"] == 0, "workspace regression tests missing or failed")
    require(acceptance["host-tests"] == acceptance["linux-tests"], "native/Linux test counts differ")
    negative_cases = {"wrong_server_pin", "untrusted_client", "wrong_space", "wrong_epoch", "membership_denied"}
    for path in ["host-host", "host-linux", "linux-linux", "linux-host"]:
        benchmark = result["benchmarks"][path]
        require(benchmark["lab_only"] and benchmark["payload_verified"], f"unverified channel payload: {path}")
        cases = acceptance[path + "-negative"]["negative_cases"]
        require(len(cases) == 5 and {c["case"] for c in cases} == negative_cases
                and all(c["rejected"] is True for c in cases), f"channel rejection coverage: {path}")
    checks.append("CHANNEL: four real TCP/mTLS paths, verified payloads, 20 refusals")
    relay = acceptance["relay-confidentiality"]
    require(relay["captured_bytes"] > 1024 and relay["canary_found"] is False, "relay plaintext probe failed")
    tamper = acceptance["relay-active-tamper"]
    require(tamper["mutated"] and tamper["authenticated_echo_refused"], "active relay tamper accepted")
    checks.append("RELAY: plaintext canary absent; active tamper refused")
    for environment in ["host", "linux"]:
        faults = acceptance[f"{environment}-storage-faults"]
        require(len(faults["sigkill_restart_trials"]) == 3, "missing SIGKILL trials")
        for trial in faults["sigkill_restart_trials"]:
            recovered = trial["recovered"]
            require(recovered["sequence"] >= trial["acknowledged_floor"]
                    and recovered["pending"] == recovered["sequence"]
                    and recovered["admission_paused"] and trial["integrity_check"] == "ok", "lost acknowledged journal prefix")
        require(faults["signature_tamper"]["rejected"] and faults["missing_outbox"]["rejected"], "journal tampering accepted")
        require(faults["independent_rollback_detection_available"] is False
                and faults["physical_power_loss_tested"] is False, "unproven trust or power-loss claim")
    trials = acceptance["container-kill-restart"]
    require(len(trials) == 3, "missing whole-container crash trials")
    for trial in trials:
        recovered = trial["recovered"]
        require(trial["container_exit"] == 137 and recovered["sequence"] >= trial["acknowledged_floor"]
                and recovered["pending"] == recovered["sequence"] and recovered["admission_paused"], "container crash recovery failed")
    checks.append("STORAGE: nine SIGKILL recoveries; evidence/mirror tampering refused")
    errors = {
        "valid_old_local_backup": "LocalRollbackOrFork",
        "old_signed_response_new_nonce": "WrongChallenge",
        "one_witness_offline": "MissingOrDuplicateWitness",
        "forged_signature": "InvalidSignature", "split_witness_histories": "SplitWitnesses",
        "local_signed_evidence_tamper": "inspect: Conflict", "local_missing_outbox": "inspect: Conflict",
        "corrupt_witness_refuses_to_sign": "inspect: Conflict",
    }
    for environment in ["host", "linux"]:
        quorum = acceptance[f"{environment}-quorum-recovery"]
        require(quorum["status"] == "passed", "quorum experiment incomplete")
        for name, reason in errors.items():
            case = quorum["checks"][name]
            require(case["rejected"] is True and case["reason"] == reason and case["exit_code"] == 1,
                    f"missing quorum refusal: {name}")
        for name in ["current_signed_history", "fresh_recheck_after_repair"]:
            case = quorum["checks"][name]
            require(case["sequence"] == 8 and case["fresh_quorum_checked"] and case["admission_paused"]
                    and case["diagnostic_only"], "healthy diagnostic did not recover safely")
        boundary = quorum["all_same_host_stores_rollback_counterexample"]
        require(boundary["sequence"] == 5 and boundary["admission_paused"], "same-host trust boundary undocumented")
        require(quorum["independent_storage_certified"] is False and quorum["production_admission_enabled"] is False
                and quorum["fixture_keys_only"] is True, "unsupported production security claim")
    checks.append("RECOVERY: 20 native/Linux cases; fresh quorum detects old local backup")
    require(result["release_state"] == "blocked" and result["performance_thresholds"] is None,
            "lab run cannot certify release or invent performance thresholds")
    for benchmark in result["benchmarks"].values():
        for metric in benchmark.get("metrics", []):
            require(metric["samples"] and all(math.isfinite(v) and v > 0 for v in metric["samples"]), "invalid performance samples")
    checks.append("BASELINE: finite measured performance samples; release gates unchanged")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    try:
        checks = validate(json.loads(args.results.read_text()))
    except (ValueError, KeyError, TypeError) as error:
        print(json.dumps({"profile": PROFILE, "state": "failed", "reason": str(error)}))
        raise SystemExit(1) from error
    print(json.dumps({"profile": PROFILE, "state": "passed", "checks": checks}))


if __name__ == "__main__":
    main()
