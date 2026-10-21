#!/usr/bin/env python3
"""Build and hash a fresh Android/server lab payload; contains no credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TARGET = 'aarch64-linux-android'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--builder-container', required=True)
    parser.add_argument('--sdk', type=Path, default=Path.home() / 'Library/Android/sdk')
    parser.add_argument('--ndk', default='27.2.12479018')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError('use a new staging directory')
    (output / 'bin').mkdir(parents=True)
    (output / 'build-logs').mkdir()
    commands = []

    def run(name, argv, env=None):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env, capture_output=True, text=True, timeout=1200)
        (output / 'build-logs' / (name + '.log')).write_text(result.stdout + '\nSTDERR:\n' + result.stderr)
        commands.append({'name': name, 'argv': list(map(str, argv)), 'exit_code': result.returncode})
        if result.returncode:
            raise RuntimeError(name + ': ' + result.stderr[-1500:])
        return result.stdout

    sources = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', *sorted((ROOT / 'crates').rglob('*.rs')),
               *sorted((ROOT / 'crates').rglob('Cargo.toml')),
               *[ROOT / 'scripts' / name for name in ['l001_android_docker.py', 'l001_android_server.py',
                                                      'l001_stage_android_server.py']]]
    sources = [p for p in sources if 'target' not in p.relative_to(ROOT).parts]
    hashes = {str(p.relative_to(ROOT)): digest(p) for p in sources}
    for path in sources:
        destination = output / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    ndk = args.sdk / 'ndk' / args.ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin'
    env = os.environ.copy()
    env.update({'CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER': str(ndk / 'aarch64-linux-android26-clang'),
                'CC_aarch64_linux_android': str(ndk / 'aarch64-linux-android26-clang'),
                'AR_aarch64_linux_android': str(ndk / 'llvm-ar')})
    build = ['cargo', 'test', '--workspace', '--all-targets', '--locked', '--no-run', '--message-format=json']

    def artifacts(text):
        return [item for item in map(json.loads, text.splitlines())
                if item.get('reason') == 'compiler-artifact' and item.get('profile', {}).get('test') and item.get('executable')]

    host = artifacts(run('host-test-inventory-build', build))
    expected = {}
    for index, item in enumerate(host):
        inventory = run('host-list-' + str(index), [item['executable'], '--list'])
        count = re.search(r'^(\d+) tests?, (\d+) benchmarks?$', inventory, re.M)
        if not count or int(count[2]):
            raise RuntimeError('unsupported test inventory: ' + inventory)
        key = (item['target']['name'], tuple(item['target']['kind']))
        if key in expected:
            raise RuntimeError('duplicate suite')
        expected[key] = int(count[1])
    android = artifacts(run('android-test-build', [*build, '--target', TARGET], env))
    binaries = []
    seen = set()
    for item in android:
        key = (item['target']['name'], tuple(item['target']['kind']))
        if key in seen or key not in expected:
            raise RuntimeError('unexpected Android suite')
        seen.add(key)
        source = Path(item['executable'])
        destination = output / 'bin' / source.name
        shutil.copy2(source, destination)
        run('strip-' + source.name, [ndk / 'llvm-strip', '--strip-debug', destination])
        binaries.append({'file': destination.name, 'name': key[0], 'kind': 'test',
                         'expected_tests': expected[key], 'sha256': digest(destination)})
    if seen != set(expected) or sum(expected.values()) < 248:
        raise RuntimeError('incomplete Android test inventory')
    run('android-release-build', ['cargo', 'build', '--workspace', '--examples', '--release', '--locked', '--target', TARGET], env)
    for name in ['l001_storage_lab', 'l001_channel_lab']:
        destination = output / 'bin' / name
        shutil.copy2(ROOT / 'target' / TARGET / 'release/examples' / name, destination)
        run('strip-' + name, [ndk / 'llvm-strip', '--strip-debug', destination])
        binaries.append({'file': name, 'name': name, 'kind': 'example', 'sha256': digest(destination)})
    run('linux-channel-build', ['docker', 'exec', args.builder_container, 'cargo', 'build', '--release', '--locked', '-p', 'loom-transport', '--example', 'l001_channel_lab'])
    run('linux-channel-copy', ['docker', 'cp', args.builder_container + ':/build/release/examples/l001_channel_lab', output / 'bin/linux_channel_lab'])
    if any(digest(ROOT / path) != value for path, value in hashes.items()):
        raise RuntimeError('source changed while building')
    manifest = {'schema': 2, 'source_commit': run('source-commit', ['git', 'rev-parse', 'HEAD']).strip(),
                'source_sha256': hashes, 'binaries': binaries, 'expected_test_count': sum(expected.values()),
                'linux_channel_sha256': digest(output / 'bin/linux_channel_lab'), 'commands': commands}
    (output / 'binary-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
