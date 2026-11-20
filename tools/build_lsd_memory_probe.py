#!/usr/bin/env python3
"""Build/sign the bounded lsd diagnostic on a real macOS/Xcode host.

Usage: python3 tools/build_lsd_memory_probe.py --output output/lsd-memory-probe
The output directory must be new. No downloads, installation, phone operations,
trust-cache loading or ambient environment capture are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

TARGET = "arm64e-apple-ios27.0"
IDENTIFIER = "org.droidvm.lsd-memory-probe"
XNU_PIN = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
XCRUN = "/usr/bin/xcrun"
CODESIGN = "/usr/bin/codesign"
# kern_memorystatus.c:9265-9268 permits root or this precise entitlement;
# mac_proc_check_memorystatus_control is an additional runtime check.
ENTITLEMENTS = {
    "com.apple.private.security.no-container": True,
    "com.apple.private.memorystatus": True,
}
CONTRACTS = {
    "bsd/sys/proc_info.h": "a4eb26cdfd3721b111f9979455d80a854625b0ef96ba4de1a4e7705f462e0f84",
    "libsyscall/wrappers/libproc/libproc.h": "37c7629819a18c5ef10d19a9bea00eb7e0bd31e0b127ecd2ae108c74f47c39e2",
    "bsd/sys/kern_memorystatus.h": "5ee30bbe691e386191154ef0ea957bc63d51b68fc2f5e7a0498acc861a4c1b06",
    "bsd/kern/kern_memorystatus.c": "1ff7c0bece16f400e65da81aa84e39d731fc1b6b663f39f7569513beec7a25f0",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version(word):
    return f"{word >> 16}.{(word >> 8) & 255}.{word & 255}"


def macho_identity(path):
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("The built executable has no complete Mach-O header")
    magic, cpu, subtype, kind, count, command_bytes, _, _ = struct.unpack_from("<8I", data)
    if (magic, cpu, subtype & 0xFFFFFF, kind) != (0xFEEDFACF, 0x100000C, 2, 2):
        raise ValueError("Require an arm64e Mach-O executable, not a host or arm64 binary")
    end = 32 + command_bytes
    if end > len(data) or count * 8 > command_bytes:
        raise ValueError("Incomplete Mach-O load commands")
    build_version = None
    signature = None
    offset = 32
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("Truncated Mach-O load command")
        command, size = struct.unpack_from("<2I", data, offset)
        if size < 8 or size % 8 or offset + size > end:
            raise ValueError("Invalid Mach-O load command extent")
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24 or build_version is not None:
                raise ValueError("Require one complete LC_BUILD_VERSION")
            platform, minimum, sdk, tools = struct.unpack_from("<4I", data, offset + 8)
            if 24 + tools * 8 != size:
                raise ValueError("Invalid LC_BUILD_VERSION tool coverage")
            if platform != 2 or minimum != 27 << 16:
                raise ValueError("Require iOS device platform and minimum iOS 27.0")
            build_version = {"platform": platform, "minimum": version(minimum), "sdk": version(sdk)}
        if command == 0x1D:  # LC_CODE_SIGNATURE
            if size != 16 or signature is not None:
                raise ValueError("Invalid or duplicate code signature command")
            start, length = struct.unpack_from("<2I", data, offset + 8)
            if not length or start < end or start + length > len(data):
                raise ValueError("The code signature does not fit the executable")
            signature = {"offset": start, "bytes": length}
        offset += size
    if offset != end or build_version is None:
        raise ValueError("Mach-O command coverage or iOS build identity is incomplete")
    return {"cpu_type": cpu, "cpu_subtype": subtype, "file_type": kind,
            "build_version": build_version, "code_signature": signature}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This builder requires macOS with real Xcode and codesign")
    source = Path(__file__).with_name("lsd_memory_probe.c").resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema": "org.droidvm.lsd-memory-probe.build.v1",
        "success": False,
        "stage": "preflight",
        "target": TARGET,
        "identifier": IDENTIFIER,
        "source": {"path": "tools/lsd_memory_probe.c", "sha256": sha256(source)},
        "builder_sha256": sha256(Path(__file__).resolve()),
        "xnu_commit": XNU_PIN,
        "source_contracts": [
            {"path": path, "sha256": digest,
             "url": f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU_PIN}/{path}"}
            for path, digest in CONTRACTS.items()
        ],
        "requested_entitlements": ENTITLEMENTS,
        "scope": {
            "only_target": {"uid": 501, "name": "lsd", "path": "/usr/libexec/lsd"},
            "active_transitions_mb": [[16, 64], [64, 16]],
            "pair_transitions_mb": [[[16, 12], [64, 64]], [[64, 64], [16, 12]]],
            "verbs": ["inspect", "raise64", "restore16", "raiseboth64", "restore16and12"],
            "kernel_commands": {"get": 8, "set": 7, "flags": 0, "properties_bytes": 16},
            "inactive_preservation": "active-only verbs preserve the observed inactive value; pair verbs change the fixed pair; both preserve attributes",
            "pair_preservation": "both attributes; only the fixed active/inactive pair changes",
            "original_default_sentinel_semantics": "unknown after GET8 expansion",
            "mutation_requires_root": True,
            "identity_checks": "PID, UID, name, executable and start sec/usec before/after",
            "identity_atomicity": "best effort; SET7 accepts PID, not a start-time token",
            "runtime_verified": False,
            "trust_cache_loaded": False,
            "phone_operated": False,
        },
        "commands": [],
    }

    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")

    def run(argv, timeout=120):
        result = subprocess.run([str(value) for value in argv], capture_output=True,
                                text=True, timeout=timeout)
        manifest["commands"].append({"stage": manifest["stage"], "argv": [str(value) for value in argv],
                                     "exit_code": result.returncode})
        save()
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, argv,
                                                output=result.stdout, stderr=result.stderr)
        return result

    save()
    try:
        for tool in (XCRUN, CODESIGN):
            if not Path(tool).is_file():
                raise FileNotFoundError("Required genuine macOS tool is missing: " + tool)
        sdk_path = run([XCRUN, "--sdk", "iphoneos", "--show-sdk-path"]).stdout.strip()
        sdk = Path(sdk_path)
        if not sdk.is_dir():
            raise ValueError("xcrun did not select an existing iPhoneOS SDK")
        manifest["sdk"] = {
            "path": sdk_path,
            "version": run([XCRUN, "--sdk", "iphoneos", "--show-sdk-version"]).stdout.strip(),
            "compiler_path": run([XCRUN, "--sdk", "iphoneos", "--find", "clang"]).stdout.strip(),
            "compiler_version": run([XCRUN, "--sdk", "iphoneos", "clang", "--version"]).stdout.strip(),
            "private_header_files_present": {
                name: (sdk / "usr/include" / name).is_file()
                for name in ("libproc.h", "sys/proc_info.h", "sys/kern_memorystatus.h")
            },
        }
        binary = output / "lsd-memory-probe"
        manifest["stage"] = "compile"
        save()
        run([XCRUN, "--sdk", "iphoneos", "clang", "-target", TARGET, "-isysroot", sdk,
             "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
             source, "-o", binary])
        manifest["unsigned_macho"] = macho_identity(binary)
        entitlements = output / "entitlements.plist"
        entitlements.write_bytes(plistlib.dumps(ENTITLEMENTS))
        manifest["stage"] = "sign"
        save()
        run([CODESIGN, "--force", "--sign", "-", "--pagesize", "4096", "--identifier", IDENTIFIER,
             "--entitlements", entitlements, binary])
        manifest["stage"] = "verify_signature"
        save()
        verified = run([CODESIGN, "--verify", "--strict", "--verbose=2", binary])
        described = run([CODESIGN, "--display", "--verbose=4", binary])
        detail = described.stdout + described.stderr
        digest = re.search(r"^CDHash=([a-f0-9]{40})$", detail, re.M)
        if (not digest or not re.search(r"^Page size=4096$", detail, re.M)
                or not re.search(r"^Identifier=" + re.escape(IDENTIFIER) + r"$", detail, re.M)
                or not re.search(r"^Signature=adhoc$", detail, re.M)):
            raise ValueError("Real codesign did not prove the requested 4K ad-hoc signature identity")
        embedded = run([CODESIGN, "--display", "--entitlements", ":-", binary])
        actual_entitlements = plistlib.loads(embedded.stdout.encode("utf8"))
        if actual_entitlements != ENTITLEMENTS:
            raise ValueError("Signed entitlements differ from this bounded diagnostic's requested ones")
        signed_macho = macho_identity(binary)
        if signed_macho["code_signature"] is None:
            raise ValueError("The signed executable has no complete code signature")
        manifest["codesign"] = {
            "verified": True, "identifier": IDENTIFIER, "cdhash": digest[1], "page_size": 4096,
            "signature": "adhoc", "embedded_entitlements": actual_entitlements,
            "verification_output": verified.stdout + verified.stderr,
            "display_output": detail,
        }
        manifest["binary"] = {"path": binary.name, "bytes": binary.stat().st_size,
                              "sha256": sha256(binary), "macho": signed_macho}
        trust = {"cdhashes": [digest[1]], "category": 3, "binary": binary.name,
                 "source": "tools/lsd_memory_probe.c SHA256 " + manifest["source"]["sha256"],
                 "target": TARGET}
        (output / "trust.json").write_text(json.dumps(trust, indent=2) + "\n", encoding="utf8")
        manifest["trust_record"] = {"path": "trust.json", "sha256": sha256(output / "trust.json"),
                                    "category": 3, "loaded": False}
        manifest["stage"] = "complete"
        manifest["success"] = True
        save()
        print(json.dumps({"success": True, "output": str(output), "binary": manifest["binary"],
                          "cdhash": digest[1]}, indent=2))
        return 0
    except Exception as error:
        failure = {"stage": manifest["stage"], "type": type(error).__name__, "message": str(error)}
        if isinstance(error, subprocess.CalledProcessError):
            failure["exit_code"] = error.returncode
            failure["diagnostic"] = ((error.stdout or "") + (error.stderr or ""))[-16384:]
        manifest["error"] = failure
        save()
        print(json.dumps({"success": False, "output": str(output), "error": failure}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
