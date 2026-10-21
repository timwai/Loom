#!/usr/bin/env python3
"""Verify this bounded evidence bundle; never approve L-001 release gates."""
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'sources/scripts'))
from l001_local_gate import validate


def read(path):
    return json.loads((HERE / path).read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    local = read('local-docker/results.json')
    validate(local)
    manifest = read('binary-manifest.json')
    count = manifest['expected_test_count']
    assert manifest['schema'] == 2 and count == local['acceptance']['host-tests']['passed'] == 268
    sources = HERE / 'sources'
    source_checks = 0
    for mapping in [local['source_sha256'], manifest['source_sha256'],
                    read('before-restart-vpn/build.json')['source_sha256'], read('vpn/build.json')['source_sha256']]:
        for name, value in mapping.items():
            path = sources / name
            if name.startswith('docs/acceptance/evidence/'):
                continue  # earlier immutable bundles remain separately referenced
            assert path.is_file() and digest(path) == value, name
            source_checks += 1
    expected_tests = {(b['name'], b['sha256'], b['expected_tests']) for b in manifest['binaries'] if b['kind'] == 'test'}
    native_results = []
    for directory in ['before-restart-native', 'native']:
        result = read(directory + '/results.json')
        assert result['state'] == 'passed' and result['source_unchanged'] is True
        assert result['release_state'] == result['platform_android_acceptance'] == 'blocked'
        assert result['tests']['passed'] == count and result['tests']['failed'] == 0 and result['tests']['execution_uid'] == 2000
        assert {(s['name'], s['sha256'], s['passed']) for s in result['tests']['suites']} == expected_tests
        assert all(c['exit_code'] == (0 if c['name'] == 'stop-android-server' and c['expected'] is None else c['expected']) for c in result['commands'])
        assert result['framework']['final_lmkd'] == 'running'
        for path in ['android-android', 'android-linux', 'linux-android']:
            bench = result['benchmarks'][path + '-bench']
            assert bench['payload_verified'] and bench['lab_only']
            cases = result['benchmarks'][path + '-rejections']['negative_cases']
            assert len(cases) == 5 and all(c['rejected'] for c in cases)
        for bench in result['benchmarks'].values():
            for metric in bench.get('metrics', []):
                assert metric['n'] == len(metric['samples']) > 0
                assert all(math.isfinite(x) and x > 0 for x in metric['samples'])
        trials = result['storage_faults']['sigkill_restart_trials']
        assert len(trials) == 3
        for trial in trials:
            assert trial['recovered']['sequence'] >= trial['acknowledged_floor']
            assert trial['recovered']['admission_paused'] and trial['integrity_check'] == 'ok'
        assert len(result['quorum_faults']['checks']) == 10
        native_results.append({'directory': directory, 'tests': count, 'suites': len(expected_tests)})
    udp = [json.loads(line) for line in (HERE / 'udp-echo.log').read_text().splitlines()]
    vpn_results = []
    for directory in ['before-restart-vpn', 'vpn']:
        result = read(directory + '/results.json')
        build = read(directory + '/build.json')
        assert result['state'] == 'passed' and len(result['cases']) == 5
        assert result['rust_jni_scope'] == build['rust_jni_scope'] == ['membership_verification', 'tun_packet_validation', 'protected_socket_factory']
        assert result['rust_jni_integrated'] and not result['production_vpn'] and not result['real_device']
        assert result['runner_sha256'] == digest(sources / 'scripts/l001_android_vpn_test.py')
        for case in ['consent_tun_protect_and_cleanup', 'system_settings_disconnect', 'app_sigkill_removes_tun']:
            value = result['cases'][case]
            if case == 'app_sigkill_removes_tun':
                assert value['tun_removed'] and value['no_unrequested_restart_after_seconds'] == 3
                value = value['before_kill']
            for field in ['rust_jni_membership_verified', 'rust_tun_packet_validated', 'rust_protect_before_connect',
                          'rust_protected_socket_closed', 'rust_protect_false_refused_before_io', 'rust_refused_socket_closed',
                          'protected_socket_bypasses_tun', 'unprotected_udp_captured_in_tun', 'unprotected_udp_echo_absent']:
                assert value[field] is True
            for refusal in ['bad_signature', 'wrong_space', 'stale_sequence', 'expired', 'truncated', 'oversized']:
                assert value['rust_refused_' + refusal] is True
        start = datetime.fromisoformat(result['started_utc']).timestamp()
        end = datetime.fromisoformat(result['finished_utc']).timestamp()
        packets = [p for p in udp if start <= p.get('time', 0) <= end]
        assert len(packets) == 6 and all(p['payload'] == 'LOOM-PROTECTED-ECHO' for p in packets), packets
        vpn_results.append({'directory': directory, 'cases': 5, 'independent_protected_datagrams': 6, 'independent_canaries': 0})
    before = read('server-before-restart.json')
    booted = read('server-after-restart.json')
    final = read('server-final.json')
    assert before['business'] == booted['business'] == final['business']
    assert all(b['running'] for b in final['business'].values())
    assert before['lab']['id'] == booted['lab']['id'] == final['lab']['id']
    assert before['lab']['started_at'] < booted['lab']['started_at'] == final['lab']['started_at']
    assert booted['framework']['system_server_pid'] == final['framework']['system_server_pid']
    for health in [before, booted, final]:
        f = health['framework']
        assert f['boot'] == '1' and f['lmkd'] == 'running' and f['app_pid'] == ''
        assert not re.search(r'\btun\d+:', f['interfaces'])
        assert f['pids_events'] == 'max 0' and not health['lab']['oom_killed']
        assert all(line.split()[1] == '0' for line in f['memory_events'].splitlines())
    cleanup = read('cleanup.json')
    assert cleanup['udp_helper_stopped'] and cleanup['stop_exit'] == 0
    assert not cleanup['lab']['running'] and not cleanup['lab']['oom_killed']
    assert cleanup['business'] == final['business']
    assert cleanup['payload_files_verified'] >= len(manifest['source_sha256']) + len(manifest['binaries'])
    release = read('release-manifest.json')
    assert release['state'] == 'blocked' and len(release['checks']) == 9
    assert all(c['state'] != 'passed' for c in release['checks'])
    assert all(value is None for value in release['signoffs'].values())
    return {'profile': 'L-001-existing-environments-v1', 'state': 'passed', 'source_hash_comparisons': source_checks,
            'local_tests_per_os': count, 'android_native': native_results, 'android_jni': vpn_results,
            'container_restart_revalidated': True, 'business_container_identities_unchanged': True,
            'production_admission_enabled': False, 'release_state': 'blocked', 'real_android_device': False,
            'windows_environment_available': False, 'macos_signed_extension_available': False,
            'independent_review_completed': False}


if __name__ == '__main__':
    print(json.dumps(main(), indent=2))
