#!/usr/bin/env python3
"""Build the isolated Apple APK with the pinned project toolchain already staged.

Use the configured system network proxy for build dependency acquisition; no
proxy credentials are stored in the source or passed on a command line.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "sources/DroidVM-Apple"
GRADLE = ROOT / "output/apk-buildenv/gradle-9.6.0/bin/gradle.bat"
JDK = Path(os.environ.get("JAVA_HOME", str(ROOT / "tools/jdk")))
SDK = Path(os.environ.get("ANDROID_HOME", str(ROOT / "tools/android-sdk")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configure-only", action="store_true")
    parser.add_argument("--list-tasks", action="store_true")
    parser.add_argument("--tests", nargs="*", default=[])
    parser.add_argument("--tests-only", action="store_true", help="Run focused JVM tests without assembleRelease")
    parser.add_argument("--edition", choices=("apple10",), default="apple10")
    args = parser.parse_args()
    if args.tests_only and not args.tests:
        parser.error("--tests-only requires an explicit --tests selection")
    if not args.tests_only and not args.configure_only and not args.list_tasks:
        from prepare_apple_apk_assets import verify_apple10_app_aidl
        verify_apple10_app_aidl(ROOT)
    if not GRADLE.is_file() or not (JDK / "bin/java.exe").is_file():
        raise FileNotFoundError("Use the staged Gradle 9.6.0 and existing JDK 21")
    environment = os.environ.copy()
    environment["JAVA_HOME"] = str(JDK)
    environment["ANDROID_HOME"] = str(SDK)
    environment["GRADLE_USER_HOME"] = os.environ.get("GRADLE_USER_HOME", str(ROOT / "output/gradle-cache"))
    command = [str(GRADLE), "--no-daemon", "--max-workers=2", "--console=plain",
               "-Dorg.gradle.jvmargs=-Xmx3g -Dfile.encoding=UTF-8",
               "-PappleAssetVerifierPython=" + sys.executable, "-PappleEdition=" + args.edition]
    proxies = urllib.request.getproxies()
    for protocol in ("http", "https"):
        proxy = proxies.get(protocol)
        if not proxy:
            continue
        parsed = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
        if parsed.username or parsed.password:
            raise ValueError("An authenticated build proxy requires credential-safe configuration")
        command += [f"-D{protocol}.proxyHost={parsed.hostname}", f"-D{protocol}.proxyPort={parsed.port or 80}"]
    if args.list_tasks:
        command += [":app:tasks", "--all"]
    elif args.configure_only:
        command += ["help"]
    else:
        if args.tests:
            command += [":app:testDebugUnitTest"]
            for test in args.tests:
                command += ["--tests", test]
        if not args.tests_only:
            command += [":app:assembleRelease"]
    print(json.dumps({"project": str(PROJECT), "application_id": "cn.classfun.droidvm.apple",
                      "tasks": ["tasks --all"] if args.list_tasks else ["help"] if args.configure_only else ["testDebugUnitTest"] if args.tests_only else ["testDebugUnitTest", "assembleRelease"] if args.tests else ["assembleRelease"],
                      "edition": args.edition,
                      "toolchain": {"gradle": "9.6.0", "jdk": "21", "ndk": "30.0.16248370"},
                      "maximum_workers": 2, "phone_modified": False}, ensure_ascii=True), flush=True)
    raise SystemExit(subprocess.run(command, cwd=PROJECT, env=environment).returncode)


if __name__ == "__main__":
    main()
