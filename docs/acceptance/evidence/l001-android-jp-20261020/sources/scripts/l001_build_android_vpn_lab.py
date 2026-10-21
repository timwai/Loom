#!/usr/bin/env python3
"""Build a standalone, debug-signed Android API probe; never a Loom client."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", type=Path, default=Path.home() / "Library/Android/sdk")
    p.add_argument("--output", type=Path, default=ROOT / "target/android-vpn-lab")
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

    def run(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=120)
        commands.append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr)

    run(["javac", "--release", "8", "-cp", android, "-d", classes, source / "ProbeActivity.java"])
    run([tools / "d8", "--min-api", "26", "--lib", android, "--output", dex, *sorted(classes.rglob("*.class"))])
    run([tools / "aapt", "package", "-f", "-M", source / "AndroidManifest.xml", "-I", android,
         "-F", output / "unsigned.apk"])
    with zipfile.ZipFile(output / "unsigned.apk", "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
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
        "source_sha256": {str(x.relative_to(ROOT)): hashlib.sha256(x.read_bytes()).hexdigest()
                          for x in [source / "ProbeActivity.java", source / "AndroidManifest.xml", Path(__file__).resolve()]},
        "commands": commands,
    }, indent=2) + "\n")
    print(apk)


if __name__ == "__main__":
    main()
