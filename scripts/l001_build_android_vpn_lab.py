#!/usr/bin/env python3
"""Build a standalone, debug-signed Android API probe; never a Loom client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", type=Path, default=Path.home() / "Library/Android/sdk")
    p.add_argument("--output", type=Path, default=ROOT / "target/android-vpn-lab")
    p.add_argument("--ndk", default="27.2.12479018")
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    classes, dex = output / "classes", output / "dex"
    for directory in (classes, dex):
        shutil.rmtree(directory, ignore_errors=True)
    classes.mkdir(exist_ok=True)
    dex.mkdir(exist_ok=True)
    tools = args.sdk / "build-tools/35.0.0"
    android = args.sdk / "platforms/android-35/android.jar"
    source = ROOT / "tools/android-vpn-lab"
    commands = []

    def run(argv, env=None):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env, capture_output=True, text=True, timeout=240)
        commands.append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr)

    native_env = os.environ.copy()
    ndk = args.sdk / "ndk" / args.ndk / "toolchains/llvm/prebuilt/darwin-x86_64/bin"
    native_env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = str(ndk / "aarch64-linux-android26-clang")
    native_env["CC_aarch64_linux_android"] = str(ndk / "aarch64-linux-android26-clang")
    native_env["AR_aarch64_linux_android"] = str(ndk / "llvm-ar")
    run(["cargo", "build", "-p", "loom-android", "--lib", "--release", "--locked", "--target", "aarch64-linux-android"], env=native_env)
    assets = output / "assets"
    run(["cargo", "run", "-p", "loom-android", "--example", "membership_fixture", "--locked", "--", assets])
    native = ROOT / "target/aarch64-linux-android/release/libloom_android.so"
    run(["javac", "--release", "8", "-cp", android, "-d", classes, *sorted(source.glob("*.java"))])
    run([tools / "d8", "--min-api", "26", "--lib", android, "--output", dex, *sorted(classes.rglob("*.class"))])
    run([tools / "aapt", "package", "-f", "-M", source / "AndroidManifest.xml", "-I", android,
         "-F", output / "unsigned.apk"])
    with zipfile.ZipFile(output / "unsigned.apk", "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
        archive.write(native, "lib/arm64-v8a/libloom_android.so")
        for item in sorted(assets.iterdir()):
            archive.write(item, "assets/" + item.name)
    run([tools / "zipalign", "-f", "4", output / "unsigned.apk", output / "aligned.apk"])
    key = output / "debug-only.p12"
    if not key.exists():
        run(["keytool", "-genkeypair", "-keystore", key, "-storepass", "android", "-keypass", "android",
             "-alias", "lab", "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
             "-dname", "CN=Loom disposable laboratory"])
        key.chmod(0o600)
    apk = output / "loom-vpn-lab.apk"
    run([tools / "apksigner", "sign", "--ks", key, "--ks-key-alias", "lab", "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--out", apk, output / "aligned.apk"])
    run([tools / "apksigner", "verify", "--verbose", "--print-certs", apk])
    (output / "build.json").write_text(json.dumps({
        "lab_only": True, "debug_signed": True, "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "rust_jni_scope": ["membership_verification", "tun_packet_validation", "protected_socket_factory"],
        "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
        "fixture": json.loads((assets / "membership.json").read_text()),
        "source_sha256": {str(x.relative_to(ROOT)): hashlib.sha256(x.read_bytes()).hexdigest()
                          for x in [*source.glob("*.java"), source / "AndroidManifest.xml", Path(__file__).resolve(),
                                    ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "crates").rglob("*.rs")),
                                    *sorted((ROOT / "crates").rglob("Cargo.toml"))] if "target" not in x.relative_to(ROOT).parts},
        "commands": commands,
    }, indent=2) + "\n")
    print(apk)


if __name__ == "__main__":
    main()
