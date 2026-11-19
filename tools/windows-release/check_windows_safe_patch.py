#!/usr/bin/env python3
"""Check the local Windows patch with git apply, XML and PowerShell parsing only.

The pinned checkout is read-only. An owned, retained verification fixture receives
the patch. No builder, driver, guest initializer or Windows deployment is run.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
BASE = "cb6469058514401f16dd4b3142fde027f5b3c94a"
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sources/win11-arm64-image-builder"
PATCH = ROOT / "patches/windows-safe-provisioning.patch"
TARGETS = ("windows/build.ps1", "windows/unattend.xml", "windows/setup-firstboot.ps1")


def command(args, cwd=None):
    completed = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True)
    return completed.stdout


def source_state():
    return {
        "head": command(["git", "-C", str(SOURCE), "rev-parse", "HEAD"]).decode().strip(),
        "tracked_changes": command(["git", "-C", str(SOURCE), "status", "--porcelain",
                                    "--untracked-files=no"]).decode(),
    }


def make_fixture():
    verification = (ROOT / "verification").resolve(strict=True)
    fixture = Path(tempfile.mkdtemp(prefix="windows-safe-patch-check-", dir=verification))
    if not fixture.resolve().is_relative_to(verification):
        raise RuntimeError("Static fixture escaped verification")
    checkout = fixture / "applied"
    checkout.mkdir()
    archive = command(["git", "-C", str(SOURCE), "archive", "--format=tar", BASE])
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for member in stream:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Unexpected source archive path")
            target = checkout.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                incoming = stream.extractfile(member)
                if incoming is None:
                    raise RuntimeError("Missing archive member data")
                with incoming:
                    target.write_bytes(incoming.read())
            else:
                raise RuntimeError("Source archive contains a non-regular member")
    command(["git", "init", "-q"], checkout)
    command(["git", "config", "core.autocrlf", "false"], checkout)
    return fixture, checkout


def parse_powershell(checkout):
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        raise RuntimeError("A local PowerShell parser is required")
    files = [str(checkout / path) for path in (TARGETS[0], TARGETS[2], "windows_build.ps1")]
    literal = ", ".join("'" + path.replace("'", "''") + "'" for path in files)
    source = """
$result = @()
foreach ($file in @(%s)) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    $result += [pscustomobject]@{
        file = $file
        errors = @($errors | ForEach-Object {
            [pscustomobject]@{line=$_.Extent.StartLineNumber; message=$_.Message}
        })
    }
}
$result | ConvertTo-Json -Depth 5 -Compress
""" % literal
    encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
    raw = command([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
    results = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(results, list):
        results = [results]
    if any(result["errors"] for result in results):
        raise RuntimeError("PowerShell parse errors: " + json.dumps(results))
    return results


def inspect_texts(checkout):
    build = (checkout / TARGETS[0]).read_text(encoding="utf-8-sig")
    firstboot = (checkout / TARGETS[2]).read_text(encoding="utf-8-sig")
    entry = (checkout / "windows_build.ps1").read_text(encoding="utf-8-sig")
    tree = ET.parse(checkout / TARGETS[1])
    namespace = {"u": "urn:schemas-microsoft-com:unattend"}
    components = tree.findall(".//u:component", namespace)
    command_text = " ".join(
        node.text or "" for name in ("Path", "CommandLine")
        for node in tree.findall(".//u:" + name, namespace)
    )
    checks = {
        "old_entry_is_only_a_checked_forwarder": 'Join-Path $PSScriptRoot "windows/build.ps1"' in entry
            and all(token not in entry for token in
                ("$env:", "Start-Process", "Set-ExecutionPolicy", "Invoke-WebRequest")),
        "admin_failure_has_no_relaunch": "Start-Process" not in build,
        "no_host_installer_or_downloader": all(token not in build for token in
            ("winget", "Invoke-WebRequest", "Read-Host", "Set-ExecutionPolicy")),
        "packaging_has_no_unreviewed_delegate": "if ($env:OUT_VMPKG)" in build
            and "this builder only creates OUT_QCOW" in build
            and 'Join-Path $SOURCE_ROOT "pack-vmpkg.ps1"' not in build,
        "explicit_temp_ownership": all(token in build for token in
            ("DVM_OWNED_ROOT", "RUNNER_TEMP", "Get-BoundedPath")),
        "alternate_parent_is_explicit": "$env:DVM_TEMP_PARENT" in build,
        "installed_driver_observation_is_actual": "Get-WindowsDriver" in build
            and "actual_offline_dism" in build and "$env:DVM_RECORD_DIR" in build,
        "native_mountvol_and_literal_cleanup": 'FilePath "mountvol"' in build
            and "cmd /c" not in build
            and "Remove-Item -LiteralPath $removePath -Recurse -Force" in build,
        "owned_vhd_before_dism": "The requested ESP/Windows letters are not bound to the owned VHDX" in build,
        "explicit_six_drivers": '@("NetKVM", "rdmapool", "pvmpower", "vioinput", "viostor", "viosnd")' in build,
        "testsigning_preserved": '"testsigning", "on"' in build,
        "no_blanket_integrity_disable": '"nointegritychecks"' not in build,
        "no_appx_resetbase_debloat": all(token not in build for token in
            ("Remove-AppxProvisionedPackage", '"ResetBase"', 'Join-Path $HERE "debloat.ps1"')),
        "no_ssh_payload_or_online_ems_marker": all(token not in build for token in
            ("OPENSSH_SRC", "SSH_PUBKEY", "authorized_keys", "ems-sac-online.flag")),
        "local_ems_only": 'if ($EMS_SAC_SOURCE -eq "online") { throw' in build
            and '"/LimitAccess"' in build
            and '"/bootems", "{bootmgr}", "on"' in build,
        "no_oobe_eula_preanswer": not tree.findall(".//u:OOBE", namespace)
            and not tree.findall(".//u:AutoLogon", namespace),
        "account_creation_kept": len(tree.findall(".//u:LocalAccount", namespace)) == 1
            and tree.find(".//u:LocalAccount/u:Name", namespace).text == "@@USERNAME@@"
            and tree.find(".//u:LocalAccount/u:Password/u:Value", namespace).text == "@@PASSWORD@@",
        "arm64_components": all(component.attrib.get("processorArchitecture") == "arm64"
                                for component in components),
        "only_local_initializers_called": "setup-firstboot.ps1 -Phase Machine" in command_text
            and "setup-firstboot.ps1 -Phase User" in command_text
            and all(token not in command_text for token in
                ("setup-ssh", "debloat", "AutoAdminLogon", "DefaultPassword", "netsh")),
        "guest_initializer_bound_and_not_installer": '"ARM64"' in firstboot
            and '"C:\\DroidVM"' in firstboot
            and all(token not in firstboot for token in
                ("msiexec", "Expand-Archive", "Invoke-WebRequest", "New-NetFirewallRule",
                 "Set-MpPreference", "wuauserv", "randomizeidentifiers")),
        "guest_cert_pvmpower_power_preserved": all(token in firstboot for token in
            ('"certutil"', '"TrustedPublisher"', "pvmpower-devnode.ps1", '"powercfg"')),
        "remote_rules_bound_to_actual_objects": "Disable-NetFirewallRule -InputObject $rule" in firstboot,
    }
    if not all(checks.values()):
        raise RuntimeError("Static coverage failed: " + json.dumps(checks))
    return checks


def main():
    before = source_state()
    if before["head"] != BASE or before["tracked_changes"]:
        raise RuntimeError("Preserve the source checkout; the required clean base is not present")
    fixture, checkout = make_fixture()
    command(["git", "apply", "--check", str(PATCH)], checkout)
    command(["git", "apply", str(PATCH)], checkout)
    parses = parse_powershell(checkout)
    checks = inspect_texts(checkout)
    after = source_state()
    if after != before:
        raise RuntimeError("The read-only source checkout changed during the static check")
    report = {
        "operation": "windows_safe_provisioning_static_patch_check",
        "base_commit": BASE,
        "patch": str(PATCH),
        "patch_bytes": PATCH.stat().st_size,
        "patch_sha256": hashlib.sha256(PATCH.read_bytes()).hexdigest(),
        "git_apply_check": "passed",
        "powershell_parse": parses,
        "xml_parse": "passed",
        "static_text_coverage": checks,
        "source_checkout_unchanged": True,
        "retained_owned_fixture": str(fixture),
        "windows_build_executed": False,
        "drivers_executed_or_installed": False,
        "guest_initializer_executed": False,
        "host_security_modified": False,
        "phone_operated": False,
        "scope": "git apply, parser and fixed source/XML coverage only; no runtime or boot claim",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    destination = fixture / "static-check.json"
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "report": str(destination), "patch_sha256": report["patch_sha256"],
                      "source_checkout_unchanged": True, "runtime_checked": False}))


if __name__ == "__main__":
    main()
