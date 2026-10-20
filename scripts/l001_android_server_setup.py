#!/usr/bin/env python3
"""Provision only the labelled ARM64 Android laboratory on a Linux Docker host.

Run as root on the authorized server. Missing kernel modules must be installed
separately for the running kernel; this script does not upgrade or reboot it.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import time

from l001_android_docker import IMAGE


def run(*args, check=True):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=180)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "restart", "stop", "status"])
    parser.add_argument("--container", default="loom-l001-android-jp")
    args = parser.parse_args()
    assert platform.system() == "Linux" and platform.machine() in ("aarch64", "arm64")
    assert os.geteuid() == 0, "kernel/device preparation requires root"
    inspected = run("docker", "inspect", args.container, check=False)
    config = json.loads(inspected.stdout)[0] if inspected.returncode == 0 else None
    if config:
        assert config["Config"].get("Labels", {}).get("loom.task") == "l001-android-remote"
        image = json.loads(run("docker", "image", "inspect", IMAGE).stdout)[0]
        assert config["Image"] == image["Id"], "unexpected image"
        for bindings in config["HostConfig"]["PortBindings"].values():
            assert all(binding["HostIp"] == "127.0.0.1" for binding in bindings)
    if args.action == "status":
        print(json.dumps({"exists": bool(config), "state": config["State"] if config else None}, indent=2))
        return
    if args.action == "stop":
        if config and config["State"]["Running"]:
            run("docker", "stop", "-t", "20", args.container)
        return
    assert Path("/proc/pressure/memory").is_file(), "host kernel must provide PSI memory pressure events"
    for module in ("binder_linux", "ip6table_filter", "ip6table_nat", "tun"):
        run("modprobe", module)
    assert Path("/dev/net/tun").exists()
    if not config:
        run("docker", "pull", IMAGE)
        run("docker", "create", "--name", args.container, "--label", "loom.task=l001-android-remote",
            "--privileged", "--cpus", "2", "--memory", "3g", "--pids-limit", "4096", "--restart", "no",
            "--device", "/dev/net/tun:/dev/tun", "-v", args.container + "-data:/data",
            "-p", "127.0.0.1:15555:5555", "-p", "127.0.0.1:18443:18443", IMAGE,
            "androidboot.use_memfd=1", "androidboot.redroid_gpu_mode=guest",
            "androidboot.redroid_width=720", "androidboot.redroid_height=1280", "androidboot.redroid_fps=15")
    else:
        run("docker", "update", "--cpus", "2", "--memory", "3g", "--pids-limit", "4096", args.container)
    if config and args.action == "restart" and config["State"]["Running"]:
        run("docker", "stop", "-t", "20", args.container)
    run("docker", "start", args.container)
    # Existing containers without --device also need Android's /dev/tun spelling
    # recreated after each start. All device changes are inside this container.
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        devices = run("docker", "exec", args.container, "sh", "-c",
            "chmod 666 /dev/binder /dev/hwbinder /dev/vndbinder && "
            "(test -e /dev/tun || mknod /dev/tun c 10 200) && chmod 666 /dev/tun", check=False)
        if devices.returncode == 0:
            health = run("docker", "exec", args.container, "sh", "-c",
                "getprop sys.boot_completed; getprop init.svc.lmkd; pidof system_server", check=False)
            lines = health.stdout.splitlines()
            if len(lines) == 3 and lines[:2] == ["1", "running"]:
                # This image's virtual Bluetooth HAL has no usable hardware address.
                run("docker", "exec", args.container, "settings", "put", "global", "bluetooth_on", "0")
                print(json.dumps({"boot_completed": True, "lmkd": "running", "system_server_pid": lines[2]}))
                return
        time.sleep(2)
    raise TimeoutError("Android framework did not become healthy; inspect container logs")


if __name__ == "__main__":
    main()
