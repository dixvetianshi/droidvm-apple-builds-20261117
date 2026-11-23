"""Sign a newly built isolated Apple APK against its selected runtime asset owner."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

from prepare_apple_apk_assets import (APPLICATION_ID, APK_RELEASES, ASSET_NAMES, ASSET_RELEASES, manifest_member_hashes,
                                      merged_record, validate_merged_record, verify_runtime_archive, verify_apple10_app_aidl)
from runtime_artifact import sha256_file

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ.get("ANDROID_HOME", str(ROOT / "tools/android-sdk"))) / "build-tools/37.0.0"
JAVA = Path(os.environ.get("JAVA_HOME", str(ROOT / "tools/jdk"))) / "bin/java.exe"
CERTIFICATE = "9640c926d5d842d2f51eb418707b5a864bb4171f0b414bdbbec67bfdc62727bd"
CHUNK = 4 * 1024 * 1024
MAC_IMPORT_CLASSES = (
    "cn/classfun/droidvm/lib/pkg/AppleMacImportPreparation",
    "cn/classfun/droidvm/lib/pkg/AppleMacPreparationResult",
    "cn/classfun/droidvm/lib/pkg/AppleGuestImportProfile",
    "cn/classfun/droidvm/lib/pkg/AppleGuestNetworkProfile",
)


def delivery_paths(edition):
    if edition not in APK_RELEASES:
        raise ValueError("Unsupported Apple APK edition")
    release = APK_RELEASES[edition]
    day = release["day"]
    label = edition.capitalize()
    return {
        "aligned": ROOT / "output/apk" / ("DroidVM-" + label + "-r242-aligned.apk"),
        "apk": ROOT / "output/apk" / ("DroidVM-0.0.6-r242-" + label + "-NX736J.apk"),
        "record": ROOT / "verification" / (edition + "-apk-delivery-" + day + ".json"),
        "signature": ROOT / "verification" / (edition + "-apk-signature-" + day + ".txt"),
        "badging": ROOT / "verification" / (edition + "-apk-badging-" + day + ".txt"),
        "checksum": ROOT / "output/apk" / ("SHA256SUMS-" + edition + ".txt"),
        "runtime_record": ROOT / ASSET_RELEASES[release["runtime_edition"]]["paths"]["record"],
    }


def validate_build_metadata(metadata, edition, version_code, unsigned_name):
    if edition not in APK_RELEASES:
        raise ValueError("Unsupported Apple APK edition")
    expected_code = APK_RELEASES[edition]["version_code"]
    if expected_code is not None and version_code != expected_code:
        raise ValueError("Version code differs from the selected Apple release")
    version = "0.0.6.r242.g3348830." + edition
    elements = metadata.get("elements") if isinstance(metadata, dict) else None
    if not isinstance(elements, list) or len(elements) != 1 or not isinstance(elements[0], dict):
        raise ValueError("The selected APK output metadata must own exactly one built APK")
    element = elements[0]
    if metadata.get("applicationId") != APPLICATION_ID \
            or element.get("versionName") != version or element.get("versionCode") != version_code \
            or element.get("outputFile") != unsigned_name:
        raise ValueError("Build output does not select the requested isolated Apple edition")
    return version


def verify_certificate(verified):
    certificates = []
    signer_counts = []
    for line in verified.splitlines():
        normalized = line.strip().lower()
        count = re.fullmatch(r"number of signers: ([1-9][0-9]*)", normalized)
        if count:
            signer_counts.append(int(count.group(1)))
        # SDK 37 reports the certificate in a named signing-scheme block. Older
        # apksigner output identifies it by signer number. Public-key digests are
        # different facts and cannot satisfy this certificate check.
        match = re.fullmatch(
            r"(?:signer #1|v[1-4](?:\.[0-9]+)? signer:) certificate sha-256 digest: ([0-9a-f]{64})",
            normalized)
        if match:
            certificates.append(match.group(1))
    if signer_counts != [1] or not certificates or set(certificates) != {CERTIFICATE}:
        raise ValueError("Signed APK certificate differs from the user's existing Apple application")


def verify_badging(badging, version, version_code):
    packages = [line for line in badging.splitlines() if line.startswith("package: ")]
    if len(packages) != 1:
        raise ValueError("Signed APK must declare one package")
    fields = dict(re.findall(r"(?:^| )([A-Za-z]+)='([^']*)'", packages[0]))
    if fields.get("name") != APPLICATION_ID or fields.get("versionCode") != str(version_code) \
            or fields.get("versionName") != version:
        raise ValueError("Signed APK package declarations differ from the selected edition")


def dex_class_strings(archive):
    descriptors = {name: ("L" + name + ";").encode("ascii") for name in MAC_IMPORT_CLASSES}
    observed = {name: False for name in descriptors}
    overlap = max(map(len, descriptors.values())) - 1
    for name in archive.namelist():
        if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name) is None:
            continue
        tail = b""
        with archive.open(name) as stream:
            for block in iter(lambda: stream.read(CHUNK), b""):
                data = tail + block
                for class_name, descriptor in descriptors.items():
                    observed[class_name] |= descriptor in data
                tail = data[-overlap:]
    return observed


def verify_apk_content(apk, runtime, edition):
    """Check the signed container against complete merged facts, never a legacy SHA literal."""
    if edition not in APK_RELEASES:
        raise ValueError("Unsupported Apple APK edition")
    release = APK_RELEASES[edition]
    owner = release["runtime_edition"]
    if runtime.get("apk_edition") != owner:
        if ASSET_RELEASES[owner]["host_policy_review"]:
            raise ValueError(edition.capitalize() + " must select its completed host read-only runtime merge record")
        raise ValueError(edition.capitalize() + " must select the completed " + owner.capitalize() + " runtime merge record")
    runtime = validate_merged_record(runtime)
    if edition == "apple10":
        verify_apple10_app_aidl(ROOT)
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Signed APK contains duplicate member identities")
        if archive.testzip() is not None:
            raise ValueError("Signed APK archive failed CRC verification")
        assets = {}
        for asset_name in ASSET_NAMES:
            with archive.open("assets/prebuilts/" + asset_name) as stream:
                assets[asset_name] = hashlib.file_digest(stream, "sha256").hexdigest()
        if assets != runtime["merged_assets_sha256"]:
            raise ValueError("APK runtime archive/JSON differs from the selected asset record")
        manifest = manifest_member_hashes(archive.read("assets/prebuilts/" + ASSET_NAMES[1]))
        if manifest != runtime["merged_member_sha256"]:
            raise ValueError("APK prebuilt JSON and merged member hashes differ")
        with archive.open("assets/prebuilts/" + ASSET_NAMES[0]) as stream:
            count = verify_runtime_archive(stream, manifest)
        facts = {
            "runtime_archive_sha256": assets[ASSET_NAMES[0]],
            "runtime_manifest_sha256": assets[ASSET_NAMES[1]],
            "runtime_regular_members_verified": count,
            "runtime_json_tar_all_member_sha256_verified": True,
            "apk_crc_verified": True, "apk_member_identities_unique": True,
        }
        if release["import_helpers"]:
            network_name = "apple-guest-network.json"
            if names.count(network_name) != 1:
                raise ValueError(edition.capitalize() + " APK must include exactly one Apple guest NAT resource")
            source = ROOT / "sources/DroidVM-Apple/app/src/main/resources" / network_name
            network = archive.read(network_name)
            if source.is_symlink() or network != source.read_bytes():
                raise ValueError("APK Apple guest NAT resource differs from the selected source")
            classes = dex_class_strings(archive)
            if not all(classes.values()):
                raise ValueError(edition.capitalize() + " APK lacks the static Mac/import helper class strings")
            facts.update({"apple_guest_network_resource_sha256": hashlib.sha256(network).hexdigest(),
                          "apple_guest_network_resource_unique_and_source_match": True,
                          "compiled_import_helper_class_strings": classes,
                          "compiled_import_helper_verification_scope": "DEX descriptor strings only; helper invocation and Android import require device verification"})
        return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edition", choices=tuple(APK_RELEASES), required=True)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--runtime-record", type=Path,
                        help="absolute path to the completed asset merge record used by this APK")
    args = parser.parse_args()
    if args.version_code <= 0:
        parser.error("--version-code must be positive")
    expected_code = APK_RELEASES[args.edition]["version_code"]
    if expected_code is not None and args.version_code != expected_code:
        parser.error(args.edition.capitalize() + " selects version code " + str(expected_code))
    paths = delivery_paths(args.edition)
    runtime_record = args.runtime_record or paths["runtime_record"]
    if not runtime_record.is_absolute():
        parser.error("--runtime-record must be an absolute path")
    runtime_record = runtime_record.resolve()
    runtime = merged_record(runtime_record)
    unsigned = ROOT / "sources/DroidVM-Apple/app/build/outputs/apk/release/app-release-unsigned.apk"
    metadata = json.loads(unsigned.with_name("output-metadata.json").read_text(encoding="utf8"))
    version = validate_build_metadata(metadata, args.edition, args.version_code, unsigned.name)
    aligned, output, record = paths["aligned"], paths["apk"], paths["record"]
    if any(paths[name].exists() for name in ("aligned", "apk", "record", "signature", "badging", "checksum")) \
            or output.with_name(output.name + ".idsig").exists():
        raise FileExistsError("Preserve existing signed outputs and selected edition records")
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(SDK / "zipalign.exe"), "-P", "16", "4", str(unsigned), str(aligned)],
                   check=True, capture_output=True)
    signer = [str(JAVA), "-jar", str(SDK / "lib/apksigner.jar")]
    # The PKCS12 key uses the keystore password. Omitting --key-pass allows the signer to reuse it.
    subprocess.run(signer + ["sign", "--ks", str(ROOT / "secrets/DroidVM-Apple-local.jks"),
                            "--ks-key-alias", "droidvm-apple", "--ks-pass",
                            "file:" + str(ROOT / "secrets/DroidVM-Apple-local.pass"),
                            "--out", str(output), str(aligned)], check=True, capture_output=True)
    verified = subprocess.run(signer + ["verify", "--verbose", "--print-certs", str(output)],
                              check=True, capture_output=True, text=True, encoding="utf8").stdout
    verify_certificate(verified)
    subprocess.run([str(SDK / "zipalign.exe"), "-c", "-P", "16", "4", str(output)],
                   check=True, capture_output=True)
    badging = subprocess.run([str(SDK / "aapt2.exe"), "dump", "badging", str(output)],
                             check=True, capture_output=True, text=True, encoding="utf8").stdout
    verify_badging(badging, version, args.version_code)
    digest = sha256_file(output)
    content = verify_apk_content(output, runtime, args.edition)
    for name, value, encoding in (("signature", verified, "utf8"), ("badging", badging, "utf8"),
                                   ("checksum", digest + "  " + output.name + "\n", "ascii")):
        with paths[name].open("x", encoding=encoding, newline="\n") as stream:
            stream.write(value)
    report = {"operation": "signed_and_verified_isolated_Apple_update",
              "created_at_utc": datetime.now(timezone.utc).isoformat(), "apk": str(output),
              "bytes": output.stat().st_size, "sha256": digest, "application_id": APPLICATION_ID,
              "apk_edition": args.edition,
              "version_code": args.version_code, "version_name": version,
              "signature_certificate_sha256": CERTIFICATE, "signature_verified": True,
              "zip_alignment_verified": True,
              "runtime_assets_record": str(runtime_record),
              "runtime_assets_record_sha256": sha256_file(runtime_record),
              "runtime_asset_edition": runtime.get("apk_edition"),
              "native_display_patch": runtime.get("native_display_patch"),
              "host_policy_source": runtime.get("host_policy_source"),
              "host_policy_review": runtime.get("host_policy_review",
                  ASSET_RELEASES[APK_RELEASES[args.edition]["runtime_edition"]]["host_policy_review"]),
              "host_policy_source_sha256": runtime.get("host_policy_source_sha256"),
              "host_policy_patch_sha256": runtime.get("host_policy_patch_sha256"),
              "source_lock_sha256": runtime.get("source_lock_sha256"),
              "shim_sha256": runtime.get("shim_sha256"),
              "phone_installed": False, "native_display_reconnect_phone_verified": False,
              "macos_automatic_import_phone_verified": False, "apple_nat_phone_verified": False,
              "original_system_packages_modified": False,
              "limitations": ["This signer does not execute Java/import tests, the native runtime or Android guest boots."]}
    report.update(content)
    if args.edition == "apple10":
        report.update(hostshare_component=runtime["hostshare_component"],
                      macos_boot_component=runtime["macos_boot_component"],
                      runtime_source_lineage=runtime["runtime_source_lineage"],
                      runtime_member_count=runtime["runtime_member_count"],
                      compiled_crosvm_sha256=runtime["compiled_crosvm_sha256"],
                      paired_app_aidl_sha256=runtime["paired_app_aidl_sha256"])
    if args.edition == "apple4":
        report.update({"runtime_payload_unchanged_from_Apple2_and_Apple3": runtime.get("apk_edition") == "apple2",
                       "inherited_import_profile_tests": "verification/apple3-apk-delivery-20261119.json"})
    with record.open("x", encoding="utf8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("apk", "bytes", "sha256", "version_name", "version_code")}))


if __name__ == "__main__":
    main()
