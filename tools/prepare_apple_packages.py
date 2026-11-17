#!/usr/bin/env python3
"""Prepare Apple package metadata from verified real build outputs; never make an OS.

prepare requires a final file record of the form {"files": {"relative/stage/path":
{"bytes": N, "sha256": "..."}}}, the upstream boot/release records in the stage,
and the firmware/runtime records made by this task's existing build helpers.
It writes metadata only. Use pack_vmpkg.py separately to create the container.
Dirty iPadOS releases also require stage/source-adjustments.json identifying
the two reviewed sparse-udif-output patches and their owning checkout states;
their original clean/changed facts remain in the preparation report.

The native importer creates a unique VM directory and does not rewrite
extra_options. After import, bind-import consumes the actual vm_import_status
event with phase=done, vm_id, vm_name, disks and boots to bind paths and VM ID.
The result must come from the phone; this tool never invents an import receipt.
Preparation/binding proves neither Android loading nor Apple guest boot.
Generated metadata contains local paths and the selected device network; keep it
local rather than uploading it with the public build helper sources.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path, PurePosixPath
import re
import sys
import time
import uuid

sys.dont_write_bytecode = True
from verify_vmpkg import (  # This module owns strict JSON and VMPKG interpretation.
    PackageError, load_manifest, load_source_map, parse_json, source_digest,
    validate_archive_path, validate_manifest,
)

MACOS_PIN = "524d27bf57ae92375aa39e3a81e11727c08973ff"
IPADOS_UNIXNU_PIN = "6efbb97764f4e39f8c682f6a6261607a2921bc7b"
IPADOS_DEVICE_PIN = "3da41eaa0f06fd21e7bc1ef17aafe0a3e72d70ff"
MACOS_FDT_SHA256 = "89952c66df5293a18a094ecb74b0166493d13e899854614e983bc4b37342f0f8"
IPADOS_SPARSE_PATCHES = {
    "unixnu": {"file": "patches/unixnu-sparse-udif.patch",
               "sha256": "4b30a8dce73e4eb40e14bf5e168faf442a328fb9d815aeab6603bd0a9e49be83"},
    "device": {"file": "patches/device-sparse-udif.patch",
               "sha256": "c78e1da35336f26493a4bbed65c5da7fa8967f7b88bc5ce5bbf95cdac3b0ea8c"},
}
# Expected rows derived from the pinned checkout_state and reviewed patch paths.
# Its git() strips stdout before splitting, removing the first row's leading
# space. Consumers keep those owner-produced rows rather than parsing status.
IPADOS_SPARSE_CHANGED = {
    "unixnu": ["M scripts/unixnu/udif.py"],
    "device": ["M ipados27/scripts/build-droidvm-root-policies.py",
               " M ipados27/scripts/root-image-identity.py"],
}
MACOS_FLAGS = {
    "MACOS_PCIE": "1", "MACOS_DATA_PCI": "1", "MACOS_NET_PCI": "1",
    "MACOS_USB_PCI": "1", "MACOS_DISPLAY": "1", "MACOS_GPU": "1",
    "MACOS_VIRTIO_GPU": "1", "MACOS_SND": "1", "MACOS_MEDIA": "1",
    "MACOS_MEDIA_VIDC": "1",
}
NETWORK_REF = "apple-uplink"


def require(condition, reason):
    if not condition:
        raise PackageError(reason)


def read_object(path):
    value = parse_json(Path(path).read_bytes(), str(path))
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def sha256_value(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value),
            f"{label}: a recorded SHA-256 is required")
    return value.lower()


def phone_path(value, parent=None):
    require(isinstance(value, str) and value.startswith("/") and
            "\\" not in value and not any(ord(c) < 32 for c in value),
            f"expected an absolute Android path: {value!r}")
    path = PurePosixPath(value)
    require(str(path) == value and ".." not in path.parts,
            f"expected a canonical Android path: {value!r}")
    if parent is not None:
        base = PurePosixPath(parent)
        require(base in path.parents, f"imported path is outside selected import directory: {value}")
    return value


def verified_file(path, expected):
    path = Path(path).resolve(strict=True)
    require(path.is_file(), f"a real file is required: {path}")
    require(isinstance(expected, dict), f"missing final file record for {path.name}")
    size = expected.get("bytes")
    require(type(size) is int and size > 0, f"missing positive recorded byte count: {path.name}")
    digest = sha256_value(expected.get("sha256"), path.name)
    require(source_digest(str(path), size) == digest, f"recorded digest mismatch: {path}")
    return {"path": str(path), "bytes": size, "sha256": digest}


def verified_digest(path, expected):
    # Some owning runtime records provide a digest without a byte count.
    path = Path(path).resolve(strict=True)
    return verified_file(path, {"bytes": path.stat().st_size, "sha256": expected})


def select_network(registry_path, selected_id):
    uuid.UUID(selected_id)
    registry = read_object(registry_path)
    networks = registry.get("networks")
    require(isinstance(networks, list), "network registry has no networks array")
    matches = [n for n in networks if isinstance(n, dict) and n.get("id") == selected_id]
    require(len(matches) == 1, "--network-id must match exactly one actual registry network")
    return copy.deepcopy(matches[0])


def ipados_source_facts(upstream, adjustments=None):
    """Admit clean pins or only the reviewed sparse UDIF adjustment; retain facts."""
    require(upstream.get("board") == "droidvm ipados-27.0.1-24A446",
            "iPadOS requires a completed release for droidvm / 24A446")
    commits, clean, changed = upstream.get("commits"), upstream.get("clean"), upstream.get("changed")
    bases = {"unixnu": IPADOS_UNIXNU_PIN, "device": IPADOS_DEVICE_PIN}
    require(isinstance(commits, dict) and all(commits.get(key) == pin for key, pin in bases.items()),
            "iPadOS release does not identify both selected pinned source checkouts")
    require(type(clean) is bool and isinstance(changed, dict),
            "iPadOS release must retain its owning clean and changed facts")
    facts = {"commits": copy.deepcopy(commits), "clean": clean, "changed": copy.deepcopy(changed)}
    if clean:
        require(not changed, "iPadOS source record claims clean but also reports checkout changes")
        return facts
    require(isinstance(adjustments, dict) and adjustments.get("kind") == "sparse-udif-output",
            "dirty iPadOS release requires source-adjustments.json for the reviewed sparse-udif-output fix")
    patches = adjustments.get("patches")
    require(isinstance(patches, dict) and patches.keys() == IPADOS_SPARSE_PATCHES.keys(),
            "source adjustment must identify exactly the reviewed unixnu and device patches")
    states = adjustments.get("checkout_states")
    require(isinstance(states, dict) and states.keys() == bases.keys(),
            "source adjustment must retain exactly both owning checkout states")
    require(adjustments.get("final_checkout_states") == states,
            "final source states must match the recorded sparse UDIF adjustments")
    for key, expected in IPADOS_SPARSE_PATCHES.items():
        patch, state = patches[key], states[key]
        require(isinstance(patch, dict) and patch.get("file") == expected["file"] and
                sha256_value(patch.get("sha256"), expected["file"]) == expected["sha256"],
                f"{key} source adjustment differs from the reviewed sparse UDIF patch")
        require(isinstance(state, dict) and state.get("commit") == bases[key] and
                state.get("changed") == IPADOS_SPARSE_CHANGED[key],
                f"{key} checkout state has another base or changes beyond the reviewed patch")
        sha256_value(state.get("digest"), f"checkout_states.{key}.digest")
    recorded_changes = {key: state["changed"] for key, state in states.items()}
    require(changed == recorded_changes,
            "iPadOS release changes differ from the owning states recorded immediately after the reviewed patches")
    facts["source_adjustments"] = copy.deepcopy(adjustments)
    return facts


def verify_runtime(args):
    builds = read_object(args.firmware_builds)
    require(isinstance(builds.get("edk2_commit"), str) and
            re.fullmatch(r"[0-9a-f]{40}", builds["edk2_commit"]),
            "firmware builds record has no source commit identity")
    rows = builds.get("firmware_builds")
    require(isinstance(rows, list), "firmware record has no firmware_builds array")
    rows = [row for row in rows if isinstance(row, dict) and row.get("guest") == args.guest]
    require(len(rows) == 1, "exactly one recorded firmware build for this guest is required")
    row = rows[0]
    require(row.get("pci_cam_mode") is False and
            row.get("virtio_gpu_enable") is (args.guest == "ipados"),
            "firmware PCI/GOP options differ from the selected guest profile")
    firmware = verified_digest(args.firmware, row.get("firmware_sha256"))
    runtime = read_object(args.crosvm_record)
    if "runtime_files" in runtime:
        members = runtime["runtime_files"]
        require(isinstance(members, dict), "owning runtime_files must be a path-to-digest object")
        expected = members.get("runtime/usr/bin/crosvm")
        flags = runtime.get("crosvm_embedded_option_names")
    else:
        members = runtime.get("verified_files", {})
        item = members.get("usr/bin/crosvm", {}) if isinstance(members, dict) else {}
        expected = item.get("sha256") if isinstance(item, dict) else None
        flags = runtime.get("crosvm_embedded_flag_names")
    crosvm = verified_digest(args.crosvm, expected)
    require(isinstance(flags, dict), "owning runtime record has no option-name observations")
    wanted = ["protected-vm-pseudo-unprotected", "virtio-mmio-gpu", "extended-status", "hugepages"]
    if args.guest == "macos":
        wanted.append("mbi-spis")
    if args.guest == "ipados":
        wanted += ["virtio-mmio-block", "virtio-mmio-input", "virtio-mmio-net"]
    if args.profile == "full":
        wanted += ["virtio-mmio-snd", "virtio-mmio-media"]
    missing = [name for name in wanted if flags.get(name) is not True]
    require(not missing, f"required runtime option observations missing: {missing}")
    return firmware, {"firmware": firmware, "crosvm": crosvm,
                      "firmware_record": str(Path(args.firmware_builds).resolve()),
                      "firmware_source_commit": builds["edk2_commit"],
                      "runtime_record": str(Path(args.crosvm_record).resolve()),
                      "required_option_names_observed": wanted,
                      "mbi_spis_option_name_observed": True if args.guest == "macos" else "not required by the iPadOS profile",
                      "android_loader_verification": "not performed",
                      "apple_guest_boot_verification": "not performed"}


def stage_files(args):
    stage = args.stage.resolve(strict=True)
    record = read_object(args.file_record)
    expected = record.get("files")
    require(isinstance(expected, dict), "--file-record requires a files object")
    names = ("boot.img", "data-store.img") if args.guest == "macos" else (
        "release/droidvm-disk.img", "release/os.img", "release/systemos.img", "release/data-store.img")
    files = {PurePosixPath(name).name: verified_file(stage / name, expected.get(name)) for name in names}
    if args.guest == "macos":
        upstream = read_object(stage / "manifest.json")
        disk = read_object(stage / "disk.json")
        require(upstream.get("commit") == MACOS_PIN and upstream.get("dirty") is False and
                upstream.get("tag") == "27.2" and upstream.get("product") == "k27",
                "macOS boot record must be the clean pinned k27 / 27.2 build")
        require(sha256_value(upstream.get("boot_img"), "manifest.boot_img") == files["boot.img"]["sha256"],
                "macOS boot file differs from its upstream manifest")
        env = upstream.get("env")
        require(isinstance(env, dict) and all(env.get(k) == v for k, v in MACOS_FLAGS.items()),
                "macOS boot record does not match the full static PCI/GPU/SND/media profile")
        require(disk.get("tag") == "27.2" and disk.get("store") == "data-store.img",
                "disk record does not identify the selected macOS container")
        logical, offset = disk.get("bytes"), disk.get("window_offset")
        require(type(logical) is int and logical > 0 and type(offset) is int and offset > 0 and
                logical + offset == files["data-store.img"]["bytes"],
                "macOS DataStore byte count differs from disk.json")
        system = disk.get("system")
        require(isinstance(system, dict) and isinstance(system.get("uuid"), str),
                "disk.json has no System volume UUID")
        uuid.UUID(system["uuid"])
        require(args.macos_fdt is not None, "--macos-fdt is required for the fixed static boot profile")
        fdt = verified_digest(args.macos_fdt, MACOS_FDT_SHA256)
        details = {"source_commit": MACOS_PIN, "system_volume_uuid": system["uuid"],
                   "fdt": fdt, "ram_base": "0x80600000", "ram_bytes": "0x13aa00000",
                   "framebuffer": "0x1bb000000+0x800000 / 1920x1080 / a8r8g8b8",
                   "drm_host_pool": "0x1bb800000+0x4000000",
                   "media_host_pool": "0x1bf800000+0x800000",
                   "mmio_gpu_snd_decoder_encoder": ["0xa000000", "0xa001000", "0xa002000", "0xa003000"],
                   "root_uuid_in_extracted_boot_adt_verification": "not performed"}
    else:
        upstream = read_object(stage / "release/release.json")
        adjustment_record = read_object(stage / "source-adjustments.json") if upstream.get("clean") is False else None
        source_facts = ipados_source_facts(upstream, adjustment_record)
        upstream_files = upstream.get("files")
        require(isinstance(upstream_files, dict), "iPadOS release has no file records")
        for name in ("droidvm-disk.img", "os.img", "systemos.img"):
            item = upstream_files.get(name)
            require(isinstance(item, dict) and item.get("bytes") == files[name]["bytes"] and
                    sha256_value(item.get("sha256"), name) == files[name]["sha256"],
                    f"iPadOS {name} differs from the upstream release")
        generation = read_object(stage / "generation/seed.json")
        seed = upstream.get("seed")
        require(isinstance(seed, dict) and seed.get("seed_sha256") == generation.get("seed_sha256"),
                "the staged Data generation differs from the release's generation")
        require(seed.get("volume_uuid") == generation.get("volume_uuid") and
                isinstance(generation.get("volume_uuid"), str), "Data generation volume UUID differs from the release")
        uuid.UUID(generation["volume_uuid"])
        name = validate_archive_path(generation.get("seed"), "generation.seed")
        require("/" not in name, "the recorded Data seed must be one generation filename")
        generation_file = verified_digest(stage / "generation" / name, generation.get("seed_sha256"))
        details = {"upstream_commits": source_facts["commits"], "source_facts": source_facts,
                   "data_generation": generation,
                   "verified_generation_file": generation_file,
                   "fdt_mode": "dynamic: DarwinBoot consumes actual RAM, CPUs and devices",
                   "data_store_is_from_final_file_record": True}
    return files, details


def extra_options(guest, profile, uid, paths, fdt_path):
    opts = ["--dump-device-tree-blob", fdt_path]
    if guest == "macos":
        opts += ["--mbi-spis", "64", "--virtio-mmio-gpu"]
    else:
        for name in ("os.img", "systemos.img", "data-store.img"):
            opts += ["--virtio-mmio-block", paths[name] + (",ro=true" if name != "data-store.img" else "")]
        opts += ["--virtio-mmio-input", "--virtio-mmio-net", "--virtio-mmio-gpu",
                 "--pre-alloc", "drm-host-mb=8" + (",media-host-mb=64" if profile == "full" else ""),
                 "--battery", "type=goldfish"]
    if profile == "full":
        if guest == "macos":
            opts += ["--pre-alloc", "media-host-mb=8"]
        opts += ["--virtio-snd", f"backend=aaudio,capture=true,num_output_devices=1,num_input_devices=1,uid={uid}",
                 "--virtio-mmio-snd"]
        kinds = ("decoder", "encoder") if guest == "macos" else ("decoder",)
        for kind in kinds:
            opts += ["--virtio-media", f"kind={kind},uid={uid}" +
                     (",vidc=true" if guest == "macos" and kind == "decoder" else "")]
        opts += ["--virtio-mmio-media"]
    return opts


def device_config(args, files, firmware):
    template = read_object(args.vm_template)
    config = copy.deepcopy(template.get("config"))
    require(isinstance(config, dict), "--vm-template must contain a native config object")
    mac = args.guest == "macos"
    width, height = (1920, 1080) if mac else (1024, 1366)
    paths = {name: str(PurePosixPath(args.phone_media_dir) / name) for name in files}
    config.update(id=str(uuid.uuid4()), name="macOS 27.2 (DroidVM)" if mac else "iPadOS 27.0.1 (DroidVM)",
                  memory_mb=5120, cpu_count=8 if mac else 4, hypervisor="gunyah", backend="crosvm",
                  protected_vm="pseudo_unprotected", hugepages=True, prepare_lend_mthp="single",
                  balloon=False, pmu=True, rng=True, smt=True, sandbox=False, auto_up=False,
                  swiotlb_mb=0, gpu_backend="gpu_virglrenderer", gpu_mode="native", gpu_api="drm2kgsl",
                  gpu_udmabuf=True, gpu_drm2kgsl_pool_mb=64 if mac else 0, gpu_host_pool_mb=0,
                  gpu_guest_pool_mb=0, gpu_guest_prealloc_mb=0, vpu_enabled=False,
                  virtio_transport="pci", shared_dirs=[], environment_variables=[])
    for old in ("usb", "display_enabled", "display_backend", "native_display_enabled", "vnc_enabled"):
        config.pop(old, None)
    config["peripherals"] = [{"type": "xhci_usb", "id": "xhci-0", "usb2_ports": 8, "usb3_ports": 8}] if mac else []
    if mac:
        config.update(cpu_affinity=":".join(f"{i}={i}" for i in range(8)), cpu_topology_auto=False,
                      cpu_capacity=",".join(f"{i}={792 if i < 6 else 1024}" for i in range(8)), cpu_clusters="0-5;6-7")
    else:
        config.update(cpu_affinity="0=2:1=3:2=4:3=5", cpu_topology_auto=True, cpu_capacity="", cpu_clusters="")
    screens = config.get("screens")
    require(isinstance(screens, dict) and isinstance(screens.get("gpu-0"), dict) and
            isinstance(screens.get("simplefb"), dict), "template has no canonical GPU/simplefb screens")
    screens["gpu-0"].update(enabled=True, exporter="native", input_enabled=True, transport_cap="gpu",
                            width=width, height=height, refresh_rate=120)
    screens["simplefb"].update(enabled=mac, exporter="none", input_enabled=False, transport_cap="gpu",
                               width=width, height=height, poll_hz=60)
    ports = config.get("serial_ports")
    require(isinstance(ports, list) and all(isinstance(p, dict) for p in ports), "template has no explicit serial ports")
    if mac:
        for port in ports:
            port["console"] = port.get("hardware") == "serial" and port.get("num") == 1
    boot_names = ("boot.img", "data-store.img") if mac else ("droidvm-disk.img",)
    config["disks"] = [{"path": paths[name], "bus": "virtio",
                        "readonly": not mac and name != "data-store.img"} for name in boot_names]
    config["boot"] = {"protocol": "uefi", "uefi": {"firmware": str(PurePosixPath(args.phone_media_dir) / "boot" / Path(firmware["path"]).name),
                       "vars_enabled": False, "vars": ""},
                      "linux": {"source": "manual", "kernel": "", "initrd": "", "cmdline": "",
                                "image": {"disk": 0, "wait": 2, "cmdline": "", "vdafix": True}}}
    config["networks"] = [{"network_id": args.network_id,
                           "mac_address": "02:44:56:4d:00:01" if mac else "02:00:00:aa:bb:01"}]
    config["extra_options"] = extra_options(args.guest, args.profile, args.app_uid, paths,
                                            str(PurePosixPath(args.phone_media_dir) / "runtime.dtb"))
    return config


def write_outputs(output, values):
    # All admission checks happen before this exclusive directory creation.
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name, value in values.items():
        with (output / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    return str(output)


def prepare(args):
    require(args.guest != "macos" or args.profile == "full", "the pinned macOS static boot supports only the full profile")
    phone_path(args.phone_media_dir)
    require(type(args.app_uid) is int and 0 < args.app_uid < 2**31, "--app-uid must be an actual positive Android app UID")
    require(isinstance(args.app_build_type, str) and bool(args.app_build_type.strip()),
            "--app-build-type must name the observed build type; it is not inferred from the beta version")
    require(not args.output.exists(), "output directory already exists; preserve it and choose another")
    network = select_network(args.network_registry, args.network_id)
    firmware, runtime = verify_runtime(args)
    files, build = stage_files(args)
    config = device_config(args, files, firmware)
    packaged_config = copy.deepcopy(config)
    packaged_config.pop("id", None)  # The native importer owns the new VM ID.
    packaged_config["networks"][0].pop("network_id")
    packaged_config["networks"][0]["pkg_network_ref"] = NETWORK_REF
    # iPadOS needs the real importer targets before its MMIO disks may be attached.
    # The package is a two-stage installation; auto_up stays false throughout.
    if args.guest == "ipados":
        packaged_config["extra_options"] = []
    packaged_network = copy.deepcopy(network)
    packaged_network.pop("id", None)
    packaged_network["pkg_network_ref"] = NETWORK_REF
    disks, sources = [], {}
    for index, (name, item) in enumerate(files.items()):
        attached = args.guest == "macos" or name == "droidvm-disk.img"
        archive = "disks/" + name
        disks.append({"name": name, "path": str(PurePosixPath(args.phone_media_dir) / name),
                      "archive_path": archive, "index": index if attached else -1,
                      "attached": attached, "readonly": args.guest == "ipados" and name != "data-store.img", "bus": "virtio",
                      "format": "raw", "size": item["bytes"], "sha256": item["sha256"]})
        sources[archive] = item["path"]
    firmware_name = Path(firmware["path"]).name
    boot = {"kind": "uefi", "name": firmware_name, "archive_path": "boots/" + firmware_name,
            "path": config["boot"]["uefi"]["firmware"], "size": firmware["bytes"], "sha256": firmware["sha256"]}
    sources[boot["archive_path"]] = firmware["path"]
    manifest = {"manifest_version": 2 if args.guest == "ipados" else 1, "format": "vmpkg",
                "created_at": int(time.time() * 1000), "app_version": "0.0.6.r242.g3348830",
                "app_version_code": 2720, "app_build_type": args.app_build_type, "compression": args.compression,
                "vm": packaged_config, "disks": disks, "boots": [boot], "networks": [packaged_network]}
    validate_manifest(json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
    plan = [{"ref": NETWORK_REF, "action": "join", "network_id": args.network_id}]
    report = {"operation": "prepared_metadata", "guest": args.guest, "profile": args.profile,
              "caller_inputs": {key: str(value) if isinstance(value, Path) else value
                                for key, value in vars(args).items() if value is not None},
              "input_files_verified": files, "file_record": str(args.file_record.resolve()),
              "build": build, "runtime": runtime, "network_registry": str(args.network_registry.resolve()),
              "selected_network": network, "network_import_plan": plan,
              "phone_import_target_dir": args.phone_media_dir, "app_uid": args.app_uid,
              "requires_post_import_binding": True, "device_config_status": "planned paths; bind to the actual completed native import result before applying",
              "linux_vm_network_association_verification": "not performed",
              "vmpkg_created": False, "phone_files_verified": False, "phone_boot_verified": False}
    instructions = ("# 使用顺序\n\n这些文件是已校验构建文件的打包元数据，尚未创建或启动系统包。\n\n"
                    "1. 在本机用 pack_vmpkg.py 和 manifest.json、source-map.json 创建并验证 .vmpkg。\n"
                    "2. 导入到 preparation-report.json 的 phone_import_target_dir；采用其中 network_import_plan 加入已选现有网络。\n"
                    "3. 保持虚拟机停止，保存实际 vm_import_status / done 事件 JSON（vm_id、vm_name、disks、boots）。导入会创建独立子目录，不能猜测其名称。\n"
                    "4. 执行本工具 bind-import --prepared 此目录 --import-result 实际结果.json --output 新目录。\n"
                    "5. 核对手机文件校验和与运行组件，再通过原生 vm_config_apply 应用绑定后的 device-config.json。\n\n"
                    "准备阶段的 device-config.json 使用计划路径。尤其 iPadOS 必须先绑定其三个 MMIO 数据盘路径才能启动。\n"
                    "运行组件记录的开关字符串只建立静态观察；Android 加载、实际设备树和苹果系统启动仍需手机验证。\n"
                    "这些输出含本机文件路径和手机网络选择，保留在本机；公开仓库仅上传工具源码。\n")
    destination = write_outputs(args.output, {"manifest.json": manifest, "source-map.json": sources,
                                "device-config.json": config, "preparation-report.json": report, "README.zh-CN.md": instructions})
    # Reuse the owning on-disk contract validation without re-reading large image bytes.
    load_source_map(Path(destination) / "source-map.json", load_manifest(Path(destination) / "manifest.json"))
    return {"operation": report["operation"], "output": destination, "requires_post_import_binding": True,
            "vmpkg_created": False, "phone_boot_verified": False}


def bind_import(args):
    prepared = args.prepared.resolve(strict=True)
    manifest = load_manifest(prepared / "manifest.json")
    report = read_object(prepared / "preparation-report.json")
    config = read_object(prepared / "device-config.json")
    receipt = read_object(args.import_result)
    if receipt.get("type") == "event":
        require(isinstance(receipt.get("data"), dict), "native event has no data object")
        receipt = receipt["data"]
    require(receipt.get("event") == "vm_import_status" and receipt.get("phase") == "done",
            "a completed native vm_import_status / done event is required")
    require(receipt.get("done") == receipt.get("total") == len(manifest.entries),
            "native import event does not report all prepared files completed")
    vm_id, vm_name = receipt.get("vm_id"), receipt.get("vm_name")
    require(isinstance(vm_id, str), "completed native import result has no VM ID")
    uuid.UUID(vm_id)
    require(isinstance(vm_name, str) and vm_name, "completed native import result has no VM name")
    target_dir = report["phone_import_target_dir"]
    by_archive = {}
    for section in ("disks", "boots"):
        placed = receipt.get(section)
        require(isinstance(placed, list) and all(isinstance(row, dict) for row in placed),
                f"native import result has no {section} placement array")
        for row in placed:
            archive = row.get("archive_path")
            require(isinstance(archive, str) and archive in manifest.entries and archive not in by_archive,
                    "native import result contains an unexpected or repeated archive path")
            entry = manifest.entries[archive]
            require(entry.section == section and row.get("size") == entry.size,
                    f"native import placement differs from the prepared manifest: {archive}")
            by_archive[archive] = phone_path(row.get("path"), target_dir)
    require(by_archive.keys() == manifest.entries.keys(), "native import result lacks prepared files")
    paths, attached, firmware = {}, [], None
    for archive, entry in manifest.entries.items():
        if entry.section == "disks":
            paths[entry.value["name"]] = by_archive[archive]
            if entry.value.get("attached", True):
                attached.append((entry.value["index"], {"path": by_archive[archive],
                                 "readonly": entry.value["readonly"], "bus": entry.value["bus"]}))
        elif entry.value["kind"] == "uefi":
            firmware = by_archive[archive]
    require(firmware is not None and attached, "native import result lacks boot firmware or boot disk")
    config["id"], config["name"] = vm_id, vm_name
    config["disks"] = [item for _, item in sorted(attached, key=lambda item: item[0])]
    config["boot"]["uefi"]["firmware"] = firmware
    disk_dir = PurePosixPath(config["disks"][0]["path"]).parent
    config["extra_options"] = extra_options(report["guest"], report["profile"], report["app_uid"], paths,
                                            str(disk_dir / "runtime.dtb"))
    config["auto_up"] = False
    binding = {"operation": "bound_import_paths", "native_import_result": str(args.import_result.resolve()),
               "caller_inputs": {"prepared": str(args.prepared), "import_result": str(args.import_result), "output": str(args.output)},
               "vm_id": vm_id, "placed_paths": by_archive,
               "paths_bound_to_native_import_result": True, "phone_file_digest_verification": "not performed",
               "network_join_during_import_verification": "not established by the event; config uses the explicitly selected existing network ID",
               "runtime_compatibility_verification": "not performed", "phone_boot_verified": False,
               "next_step": "Verify device file digests and runtime, then apply this config using the current native config revision."}
    destination = write_outputs(args.output, {"device-config.json": config, "binding-report.json": binding})
    return {"operation": binding["operation"], "output": destination, "vm_id": vm_id, "phone_boot_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare", help="verify real stage inputs and prepare package metadata")
    prepare_parser.add_argument("--guest", choices=("macos", "ipados"), required=True)
    prepare_parser.add_argument("--profile", choices=("full", "basic"), default="full")
    for name in ("stage", "file-record", "vm-template", "firmware", "firmware-builds", "crosvm", "crosvm-record", "network-registry", "output"):
        prepare_parser.add_argument("--" + name, type=Path, required=True)
    prepare_parser.add_argument("--network-id", required=True)
    prepare_parser.add_argument("--app-uid", type=int, required=True)
    prepare_parser.add_argument("--app-build-type", required=True)
    prepare_parser.add_argument("--phone-media-dir", required=True, help="explicit parent directory selected for native import")
    prepare_parser.add_argument("--macos-fdt", type=Path)
    prepare_parser.add_argument("--compression", choices=("gzip", "none"), default="gzip")
    bind_parser = commands.add_parser("bind-import", help="bind actual native importer placements without contacting the phone")
    for name in ("prepared", "import-result", "output"):
        bind_parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args) if args.command == "prepare" else bind_import(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
