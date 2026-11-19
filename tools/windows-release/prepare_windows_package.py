#!/usr/bin/env python3
"""Prepare a real Windows ARM64 VMPKG and bind its private vars after native import.

This tool does not build Windows, pack image bytes, contact a phone or mint VM IDs.
It reuses the existing VMPKG contracts. The large disk's recorded digest is checked
by pack_vmpkg while writing; preparation checks its size and small QCOW2 header.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import uuid

from verify_vmpkg import (
    CHUNK_SIZE, PackageError, SOURCE_HEAD, load_manifest, load_source_map,
    parse_json, validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise PackageError(message)


def object_file(path):
    path = Path(path)
    require(path.is_file(), f"Required real JSON file is missing: {path}")
    path = path.resolve(strict=True)
    require(path.is_file(), f"Expected a real JSON file: {path}")
    raw = path.read_bytes()
    value = parse_json(raw, str(path))
    require(isinstance(value, dict), f"Expected a JSON object: {path}")
    return value, raw, path


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_file(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(CHUNK_SIZE):
            result.update(block)
    return result.hexdigest()


def phone_path(value):
    require(isinstance(value, str) and value.startswith("/") and "\\" not in value,
            "An absolute canonical Android path is required")
    require(not any(ord(char) < 32 for char in value), "Android path contains a control character")
    path = PurePosixPath(value)
    require(str(path) == value and ".." not in path.parts, "Android path is not canonical")
    return path


def load_profile(path):
    profile, raw, resolved = object_file(path)
    require(profile.get("format") == "droidvm-windows-arm64-profile-v1", "Unsupported Windows profile")
    app, vm = profile.get("target_application"), profile.get("vm")
    require(isinstance(app, dict) and app.get("source_commit") == SOURCE_HEAD,
            "Windows profile must target the reviewed r242 native contract")
    require(isinstance(vm, dict) and "id" not in vm, "Profile requires a VM template without a device UUID")
    require(vm.get("backend") == "crosvm" and vm.get("hypervisor") == "gunyah",
            "This Windows profile requires explicit crosvm/Gunyah")
    require(vm.get("protected_vm") == "protected_without_firmware" and vm.get("auto_up") is False,
            "Windows profile requires the selected protection and stopped initial configuration")
    require(vm.get("extra_options") == [] and vm.get("networks") == [{}],
            "This profile uses no extra path options and one unbound NIC")
    require(profile.get("network_mode") == "unbound_nic", "Unsupported Windows network mode")
    return profile, raw, resolved


def qcow2_header(path, expected_virtual_size):
    with path.open("rb") as stream:
        raw = stream.read(104)
    require(len(raw) >= 72 and raw[:4] == b"QFI\xfb", "Windows disk is not a QCOW2 image")
    version = struct.unpack_from(">I", raw, 4)[0]
    backing_offset, backing_size = struct.unpack_from(">QI", raw, 8)
    cluster_bits = struct.unpack_from(">I", raw, 20)[0]
    virtual_size = struct.unpack_from(">Q", raw, 24)[0]
    crypt_method = struct.unpack_from(">I", raw, 32)[0]
    require(version in (2, 3), "Unsupported QCOW2 version")
    require(9 <= cluster_bits <= 21, "Invalid QCOW2 cluster size")
    require(backing_offset == backing_size == 0, "Windows package requires a standalone disk without external backing")
    require(crypt_method == 0, "Encrypted QCOW2 disk is outside this Windows profile")
    require(virtual_size == expected_virtual_size, "Windows disk virtual size differs from the selected profile")
    if version == 3:
        require(len(raw) >= 104 and struct.unpack_from(">I", raw, 100)[0] >= 104,
                "Truncated or invalid QCOW2 v3 header")
        incompatible_features = struct.unpack_from(">Q", raw, 72)[0]
        require(not incompatible_features & (1 << 2), "QCOW2 external data files cannot be carried by this standalone Windows package")
    return {"format": "qcow2", "version": version, "virtual_size": virtual_size,
            "cluster_bits": cluster_bits, "external_backing": False}


def actual_stage(stage, profile):
    stage = Path(stage)
    require(stage.is_dir(), f"Completed real Windows source stage is missing: {stage}; build and receive the actual image first")
    stage = stage.resolve(strict=True)
    record, raw, record_path = object_file(stage / "build-record.json")
    require(record.get("format") == "droidvm-windows-build-record-v1"
            and record.get("status") == "complete"
            and record.get("evidence_mode") == "actual_windows_build",
            "Windows stage requires an actual completed build/receipt record; pending or synthetic inputs cannot be packaged")
    require(not any(record.get(key) is True for key in ("fixture_only", "synthetic", "test_only")),
            "Synthetic fixtures cannot be prepared as a Windows deliverable")
    windows, files = record.get("windows"), record.get("files")
    require(isinstance(windows, dict) and windows.get("architecture") == "arm64",
            "Build record must identify the actual Windows ARM64 image")
    require(isinstance(record.get("source"), dict) and bool(record["source"]), "Actual build/source provenance is required")
    require(isinstance(files, dict), "Build record requires a files map")
    names = [profile["image"]["name"], profile["firmware"]["name"], profile["firmware"]["vars_name"]]
    selected = {}
    for name in names:
        require(isinstance(name, str) and PurePosixPath(name).name == name and "\\" not in name,
                "Profile source names must be single filenames")
        item = files.get(name)
        require(isinstance(item, dict), f"Missing actual file record: {name}")
        size, expected = item.get("bytes"), item.get("sha256")
        require(type(size) is int and size > 0, f"Missing positive actual size: {name}")
        require(isinstance(expected, str) and len(expected) == 64
                and all(char in "0123456789abcdefABCDEF" for char in expected), f"Missing recorded SHA-256: {name}")
        path = (stage / name).resolve(strict=True)
        require(path.parent == stage and path.is_file() and path.stat().st_size == size, f"Actual staged file/size differs: {name}")
        checked = name != names[0]
        if checked:
            require(digest_file(path) == expected.lower(), f"Firmware/vars digest mismatch: {name}")
        selected[name] = {"path": str(path), "bytes": size, "sha256": expected.lower(),
                          "sha256_recomputed_during_preparation": checked}
    header = qcow2_header(Path(selected[names[0]]["path"]), profile["image"]["virtual_size"])
    return selected, header, {"path": str(record_path), "sha256": sha(raw),
                              "status": record["status"], "evidence_mode": record["evidence_mode"]}, windows


def write_new_directory(output, files):
    output = Path(output).resolve()
    require(not output.exists(), "Output exists; preserve it and select a new directory")
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    return output


def prepare_package(stage, profile_path, output, phone_import_dir=None, compression="gzip"):
    profile, profile_raw, profile_path = load_profile(profile_path)
    selected, header, record, windows = actual_stage(stage, profile)
    target = str(phone_path(phone_import_dir or profile["phone_import_target_dir"]))
    require(compression in ("gzip", "none"), "Compression must be gzip or none")
    image, firmware, varfile = profile["image"]["name"], profile["firmware"]["name"], profile["firmware"]["vars_name"]
    archive = {"image": "disks/" + image, "firmware": "boots/" + firmware, "vars": "disks/" + varfile}
    vm = copy.deepcopy(profile["vm"])
    vm["boot"] = {"protocol": "uefi", "uefi": {"firmware": target + "/boot/" + firmware, "vars_enabled": False, "vars": ""}}
    vm["disks"] = []
    app = profile["target_application"]
    manifest = {"manifest_version": 2, "format": "vmpkg", "created_at": int(datetime.now(timezone.utc).timestamp() * 1000),
                "app_version": app["version"], "app_version_code": app["version_code"], "app_build_type": app["build_type"],
                "compression": compression, "vm": vm, "disks": [], "boots": [], "networks": []}
    sources = {}
    for name, slot, attached, role in [(image, 0, True, "image"), (varfile, -1, False, "vars")]:
        item = selected[name]
        manifest["disks"].append({"index": slot, "name": name, "path": target + "/" + name, "readonly": False,
                                  "bus": "virtio", "format": "qcow2" if attached else "raw", "size": item["bytes"],
                                  "archive_path": archive[role], "attached": attached, "sha256": item["sha256"]})
        sources[archive[role]] = item["path"]
    item = selected[firmware]
    manifest["boots"].append({"kind": "uefi", "name": firmware, "path": target + "/boot/" + firmware,
                              "size": item["bytes"], "archive_path": archive["firmware"], "sha256": item["sha256"]})
    sources[archive["firmware"]] = item["path"]
    manifest_raw, source_raw = json_bytes(manifest), json_bytes(sources)
    validate_manifest(manifest_raw)
    report = {"format": "droidvm-windows-preparation-v1", "operation": "prepared_windows_package_inputs",
              "profile": {"path": str(profile_path), "sha256": sha(profile_raw)}, "build_record": record,
              "windows_metadata": windows, "input_files": selected, "qcow2_header": header,
              "phone_import_target_dir": target, "archive_paths": archive, "manifest_sha256": sha(manifest_raw),
              "source_map_sha256": sha(source_raw), "requires_post_import_vars_binding": True,
              "initial_uefi_vars_enabled": False, "network_mode": "unbound_nic", "vm_uuid_minted": False,
              "large_disk_sha256_recomputed_during_preparation": False,
              "disk_digest_next_check": "pack_vmpkg validates the recorded expected SHA-256 while writing actual disk bytes",
              "vmpkg_created": False, "phone_operated": False, "android_loader_verified": False, "phone_boot_verified": False}
    readme = ("# Windows ARM64 打包元数据\n\n"
              "本目录只准备真实来源的打包元数据，尚未创建系统包或连接手机。\n\n"
              "1. 用 pack_vmpkg.py --manifest 本目录/manifest.json --sources 本目录/source-map.json --output 新文件.vmpkg 创建并逐成员校验真实包。\n"
              "2. 在 DroidVM 原生界面导入实际包。默认父目录为 /storage/emulated/0/DroidVM，可另选；准备报告中的目录只是计划，不强制界面的选择。导入器自动重映射普通磁盘与 UEFI。\n"
              "3. 保持 Windows VM 停机，菜单“编辑”进入“启动”页/UEFI，打开“启用 UEFI 变量(pflash)”。点“UEFI 变量(留空 = 内置 EDK2 变量)”右侧浏览，在“选择 UEFI 变量文件”中点“选择外部文件”。\n"
              "4. 选择此次实际导入目录内、与 Windows11.qcow2 同层的 edk2-windows.vars.fd；固件在 boot/ 子目录。点右下勾号保存，重新打开核对实际私有路径和开关。vars 不作为普通来宾盘附加。\n"
              "5. NIC 初始未绑定。通过原生 VM 编辑界面加入现有网络并保存；br-wifi 等显示名不能替代实际选择。\n\n"
              "上面是原生界面主流程，不必导出 RPC JSON。界面与保存路径已按 r242 源码核对，手机加载/启动仍未实测。\n\n"
              "可选进阶：保存真正的 vm_import_status / phase=done 回执和同 UUID 当前 vm_get 响应后，可执行本工具 bind-import --prepared 本目录 --import-result 真实回执.json --vm-get-result 真实响应.json --output 新目录。工具以真实 placement 和当前配置核对实际 VM 目录，仅更新私有 vars 路径/开关，保留其它当前字段；准备时的父目录不充当实际导入边界。\n"
              "进阶工具不连接手机；生成完整配置后经实际 vm_modify/config 与 UI 持久保存流程应用，再读回核验。\n\n"
              "SBSA、SimpleFB、chunked MTHP 是 r242 已有源码字段。此准备不证明手机运行库加载、Windows 启动、驱动或持久化。\n")
    destination = write_new_directory(output, {"manifest.json": manifest_raw, "source-map.json": source_raw,
                                               "README.zh-CN.md": readme.encode("utf-8"), "preparation-report.json": json_bytes(report)})
    load_source_map(destination / "source-map.json", load_manifest(destination / "manifest.json"))
    return {"operation": report["operation"], "output": str(destination), "requires_post_import_vars_binding": True,
            "vmpkg_created": False, "phone_boot_verified": False}


def completed_placements(manifest, receipt):
    if receipt.get("type") == "event":
        receipt = receipt.get("data")
    require(isinstance(receipt, dict) and receipt.get("event") == "vm_import_status" and receipt.get("phase") == "done",
            "A genuine completed native vm_import_status/done event is required")
    require(type(receipt.get("done")) is int and type(receipt.get("total")) is int
            and receipt["done"] == receipt["total"] == len(manifest.entries), "Import receipt does not report all files completed")
    require(isinstance(receipt.get("vm_id"), str) and isinstance(receipt.get("vm_name"), str) and receipt["vm_name"],
            "Completed import receipt requires VM ID and name")
    try:
        uuid.UUID(receipt["vm_id"])
    except ValueError as error:
        raise PackageError("Native import VM ID is not a UUID") from error
    placed = {}
    for section in ("disks", "boots"):
        rows = receipt.get(section)
        require(isinstance(rows, list), f"Import receipt requires {section} placement records")
        for row in rows:
            require(isinstance(row, dict), "Malformed import placement")
            name = row.get("archive_path")
            require(isinstance(name, str) and name in manifest.entries and name not in placed, "Unknown or repeated import placement")
            entry = manifest.entries[name]
            require(entry.section == section and type(row.get("size")) is int and row["size"] == entry.size,
                    "Import placement size or section differs from manifest")
            if section == "disks":
                require(type(row.get("index")) is int and row["index"] == entry.value["index"]
                        and row.get("attached") is entry.value.get("attached", True)
                        and row.get("readonly") is entry.value["readonly"]
                        and row.get("bus") == entry.value["bus"] and row.get("format") == entry.value["format"],
                        "Native disk placement attributes differ from the Windows manifest")
            else:
                require(row.get("kind") == entry.value["kind"], "Native boot placement kind differs from manifest")
            placed[name] = str(phone_path(row.get("path")))
            require(row.get("name") == PurePosixPath(placed[name]).name, "Native placement name differs from its actual path")
    require(placed.keys() == manifest.entries.keys(), "Import receipt lacks prepared files")
    require(len(set(placed.values())) == len(placed), "Native import placements reuse the same destination path")
    return receipt, placed


def bind_config(manifest, report, receipt, vm_get_result):
    receipt, placed = completed_placements(manifest, receipt)
    require(isinstance(vm_get_result, dict) and vm_get_result.get("success") is not False,
            "A successful current native vm_get response is required")
    current = vm_get_result.get("data")
    require(isinstance(current, dict) and isinstance(current.get("id"), str), "vm_get response has no full VM config in data")
    try:
        same_id = uuid.UUID(current["id"]) == uuid.UUID(receipt["vm_id"])
    except ValueError as error:
        raise PackageError("vm_get config ID is not a UUID") from error
    require(same_id, "vm_get result belongs to a different VM than the import event")
    require(isinstance(current.get("name"), str) and current["name"], "vm_get response has no current display name")
    archive = report["archive_paths"]
    image_path, firmware_path, vars_path = (placed[archive[key]] for key in ("image", "firmware", "vars"))
    image_dir = PurePosixPath(image_path).parent
    require(PurePosixPath(vars_path).parent == image_dir and PurePosixPath(firmware_path).parent == image_dir / "boot",
            "Import placements do not share the native VM directory")
    vars_entry = manifest.entries[archive["vars"]]
    require(vars_entry.section == "disks" and vars_entry.value.get("attached") is False and vars_entry.value.get("index") == -1,
            "Private vars must be the detached Windows manifest payload")
    disks = current.get("disks")
    require(isinstance(disks, list) and any(isinstance(disk, dict) and disk.get("path") == image_path for disk in disks),
            "Current VM does not retain the imported Windows disk path")
    require(not any(isinstance(disk, dict) and disk.get("path") == vars_path for disk in disks),
            "Private vars are currently attached as a guest disk; detach them before binding")
    boot = current.get("boot")
    require(isinstance(boot, dict) and boot.get("protocol") == "uefi" and isinstance(boot.get("uefi"), dict)
            and boot["uefi"].get("firmware") == firmware_path, "Current VM firmware differs from the completed Windows import")
    config = copy.deepcopy(current)
    config["boot"]["uefi"]["vars"] = vars_path
    config["boot"]["uefi"]["vars_enabled"] = True
    return config, receipt, placed


def bind_import(prepared, import_result, vm_get_result, output):
    prepared = Path(prepared).resolve(strict=True)
    manifest = load_manifest(prepared / "manifest.json")
    report, _, _ = object_file(prepared / "preparation-report.json")
    require(report.get("format") == "droidvm-windows-preparation-v1"
            and report.get("operation") == "prepared_windows_package_inputs"
            and report.get("requires_post_import_vars_binding") is True
            and report.get("manifest_sha256") == sha(manifest.raw), "Prepared Windows manifest/report identity mismatch")
    receipt, receipt_raw, receipt_path = object_file(import_result)
    current, current_raw, current_path = object_file(vm_get_result)
    config, receipt_data, placed = bind_config(manifest, report, receipt, current)
    config_raw = json_bytes(config)
    binding = {"operation": "bound_windows_private_uefi_vars", "prepared": str(prepared),
               "native_import_result": {"path": str(receipt_path), "sha256": sha(receipt_raw)},
               "native_vm_get_result": {"path": str(current_path), "sha256": sha(current_raw)},
               "vm_id": receipt_data["vm_id"], "vm_name": config["name"],
               "import_vm_name": receipt_data["vm_name"], "placed_paths": placed,
               "actual_vm_directory": str(PurePosixPath(placed[report["archive_paths"]["image"]]).parent),
               "preparation_import_parent_plan": report.get("phone_import_target_dir"),
               "preparation_parent_used_as_actual_boundary": False,
               "modified_fields": ["boot.uefi.vars", "boot.uefi.vars_enabled"], "config_sha256": sha(config_raw),
               "other_vm_fields_preserved": True, "network_choices_preserved_from_vm_get": True,
               "phone_file_digests_verified": False, "vm_stopped_status_verified": False,
               "phone_operated": False, "config_applied_or_ui_saved": False, "phone_boot_verified": False,
               "next_step": "Keep VM stopped; verify phone file digests, apply config through the real vm_modify/UI save flow, then vm_get and persistence readback. This offline tool performs none of those phone operations."}
    destination = write_new_directory(output, {"device-config.json": config_raw, "binding-report.json": json_bytes(binding)})
    return {"operation": binding["operation"], "output": str(destination), "vm_id": receipt_data["vm_id"], "phone_boot_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="prepare only an actually received completed Windows stage")
    prep.add_argument("--stage", type=Path, default=ROOT / "output/windows-stage")
    prep.add_argument("--profile", type=Path, default=ROOT / "profiles/windows11-arm64.json")
    prep.add_argument("--output", type=Path, default=ROOT / "output/windows-package")
    prep.add_argument("--phone-import-dir")
    prep.add_argument("--compression", choices=("gzip", "none"), default="gzip")
    bind = commands.add_parser("bind-import", help="bind private vars from a real import event and current vm_get")
    for name in ("prepared", "import-result", "vm-get-result", "output"):
        bind.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_package(args.stage, args.profile, args.output, args.phone_import_dir, args.compression)
        else:
            result = bind_import(args.prepared, args.import_result, args.vm_get_result, args.output)
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **result}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
