// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.disk.DiskBus;
import cn.classfun.droidvm.lib.store.vm.VMConfig;
import cn.classfun.droidvm.ui.disk.create.DiskFormat;

/**
 * The two verified NX736J images built for r242. Names are display text, not identity:
 * automatic configuration requires their complete declared content and device profile,
 * followed by the native importer's successful per-member byte verification.
 */
public final class AppleGuestImportProfile {
    private AppleGuestImportProfile() {}

    public enum Guest {
        MACOS,
        IPADOS
    }

    static final class Member {
        final String archive;
        final long bytes;
        final String sha256;
        final int index;
        final boolean readonly;
        final boolean attached;

        Member(String archive, long bytes, String sha256, int index,
               boolean readonly, boolean attached) {
            this.archive = archive;
            this.bytes = bytes;
            this.sha256 = sha256;
            this.index = index;
            this.readonly = readonly;
            this.attached = attached;
        }

        boolean matches(DiskEntry disk) {
            return archive.equals(disk.archivePath) && bytes == disk.size
                && sha256.equalsIgnoreCase(disk.sha256) && disk.ref != null
                && disk.ref.index == index && disk.ref.readonly == readonly
                && disk.ref.bus == DiskBus.VIRTIO && disk.format == DiskFormat.RAW
                && disk.attached == attached && disk.backingArchive.isEmpty();
        }
    }

    private static final List<Member> MAC_DISKS = List.of(
        new Member("disks/boot.img", 402653184L,
            "991125c52d9e1becee16a39c670f8573ed8c0ddb64b06c7c578e7083973c45d1", 0, false, true),
        new Member("disks/data-store.img", 51541188608L,
            "290221956ea4c2d42504a2885427e60e01be86e144b225b777b54263a916ddd0", 1, false, true)
    );
    private static final List<Member> IPAD_DISKS = List.of(
        new Member("disks/droidvm-disk.img", 335544320L,
            "5d62008d8f5b5e5e4a1ad952a1520f37a9aa4f35e00b6853770dba4be243709c", 0, true, true),
        new Member("disks/os.img", 9613344768L,
            "8a12cdad43f8f0d33dadcf01a800a560222baf40c05f71374c460ba57ba3a739", -1, true, false),
        new Member("disks/systemos.img", 6016729088L,
            "d5b4873d35c85f96eaafaa31c59602b485afe33b5067eff1af67ba31204cdb4a", -1, true, false),
        new Member("disks/data-store.img", 17179869184L,
            "8f2aaec406990e150b5c701b25fd231338a92b8063555a0734fd30d8494a8967", -1, false, false)
    );

    private static final String LEGACY_IPAD_BOOT_SHA256 =
        "8bedfd8dc7ffde37d35d8c49816d404f7c27deedb85d460534c365324027638f";

    /** Refuse the known unsafe boot member before the native importer writes disks. */
    public static void requireSupportedImport(@Nullable PackageManifest manifest)
        throws IOException {
        if (manifest == null) return;
        for (var disk : manifest.disks) {
            // Names/VM/header edits cannot turn this exact old iPad boot into an
            // ordinary import. Other packages retain their existing import path.
            if (disk.ref != null && disk.ref.index == 0 && disk.attached && disk.ref.readonly
                && disk.ref.bus == DiskBus.VIRTIO && disk.format == DiskFormat.RAW
                && disk.size == 335544320L
                && LEGACY_IPAD_BOOT_SHA256.equalsIgnoreCase(disk.sha256))
                throw new IOException("这是旧版 iPadOS 启动内核包。请选择与 Apple10 配套的修复版 iPadOS .vmpkg 后再导入。");
        }
    }

    /** Source identity is owned here; preparation metadata reuses these parsed facts. */
    static Member macMember(String archive) {
        for (var member : MAC_DISKS) if (member.archive.equals(archive)) return member;
        throw new IllegalArgumentException("Unknown verified macOS source member");
    }

    static void requireVerifiedMacSources(List<DiskEntry> disks, List<BootFile> boots)
        throws IOException {
        var sources = sourceDisks(Guest.MACOS, disks);
        for (var disk : sources.values()) {
            if (!disk.sha256Verified)
                throw new IOException("macOS preparation requires verified original member bytes");
        }
        if (boots.size() != 1 || !matchesFirmware(Guest.MACOS, boots.get(0))
            || !boots.get(0).sha256Verified)
            throw new IOException("macOS preparation requires verified original firmware bytes");
    }

    private static Map<String, DiskEntry> sourceDisks(Guest guest, List<DiskEntry> placed)
        throws IOException {
        var expected = members(guest);
        if (placed.size() != expected.size())
            throw new IOException("Apple import disk source count is incomplete");
        var disks = new HashMap<String, DiskEntry>();
        for (var disk : placed) {
            if (disks.put(disk.archivePath, disk) != null)
                throw new IOException("Apple import repeats a disk member");
        }
        for (var spec : expected) {
            var disk = disks.get(spec.archive);
            if (disk == null || !spec.matches(disk))
                throw new IOException("Apple import disk source identity differs from its profile");
        }
        return disks;
    }

    @NonNull
    private static List<Member> members(Guest guest) {
        return guest == Guest.MACOS ? MAC_DISKS : IPAD_DISKS;
    }

    @NonNull
    private static String firmwareArchive(Guest guest) {
        return guest == Guest.MACOS ? "boots/edk2-macos.fd" : "boots/edk2-virtio-gpu.fd";
    }

    private static boolean matchesFirmware(Guest guest, BootFile boot) {
        var sha = guest == Guest.MACOS
            ? "124ca25827ddb328a666dbac8698e079f47f7208c2dfa582d07cc33fd0a24141"
            : "1d68346fa2df7c4775b3ca06fb7ac3992b7160600669ea3d8a560eab3dd360a2";
        return firmwareArchive(guest).equals(boot.archivePath) && "uefi".equals(boot.kind)
            && boot.size == 4194304L && sha.equalsIgnoreCase(boot.sha256);
    }

    private static boolean matchesVm(Guest guest, VMConfig vm) {
        return matchesVm(guest, vm, false);
    }

    private static boolean matchesVm(Guest guest, VMConfig vm, boolean preparedMac) {
        var item = vm.item;
        long memoryMb = item.optLong("memory_mb", 0);
        return item.optLong("cpu_count", 0) == (guest == Guest.MACOS ? 8 : 4)
            // The original iPad package declared 5 GiB; its dynamic ADT also supports
            // the user's validated 4 GiB recipe. macOS is 4 GiB only after preparation.
            && (preparedMac ? memoryMb == 4096
                : memoryMb == 5120 || guest == Guest.IPADOS && memoryMb == 4096)
            && "crosvm".equals(item.optString("backend", ""))
            && "gunyah".equals(item.optString("hypervisor", ""))
            && "pseudo_unprotected".equals(item.optString("protected_vm", ""))
            && "pci".equals(item.optString("virtio_transport", ""))
            && item.optBoolean("hugepages", false);
    }

    @Nullable
    public static Guest identify(@Nullable PackageManifest manifest) {
        if (manifest == null || !"vmpkg".equals(manifest.format)
            || !"0.0.6.r242.g3348830".equals(manifest.appVersion)
            || manifest.appVersionCode != 2720 || !"release".equals(manifest.appBuildType))
            return null;
        for (var guest : Guest.values()) {
            if (manifest.manifestVersion != (guest == Guest.MACOS ? 1 : 2)
                || !matchesVm(guest, manifest.vm) || manifest.boots.size() != 1
                || !matchesFirmware(guest, manifest.boots.get(0))) continue;
            var expected = members(guest);
            if (manifest.disks.size() != expected.size()) continue;
            var seen = new HashMap<String, DiskEntry>();
            for (var disk : manifest.disks) {
                if (seen.put(disk.archivePath, disk) != null) return null;
            }
            boolean matched = true;
            for (var spec : expected) {
                var disk = seen.get(spec.archive);
                if (disk == null || !spec.matches(disk)) { matched = false; break; }
            }
            if (matched) return guest;
        }
        return null;
    }

    /**
     * Bind only native completion facts. All validation precedes mutation; the importer
     * registers this actual config and leaves it stopped before exposing its DONE event.
     */
    public static void bind(
        @NonNull Guest guest, @NonNull VMConfig vm,
        @NonNull List<DiskEntry> placedDisks, @NonNull List<BootFile> placedBoots,
        int done, int total, int appUid
    ) throws IOException {
        bind(guest, vm, placedDisks, placedBoots, done, total, appUid, null);
    }

    public static void bind(
        @NonNull Guest guest, @NonNull VMConfig vm,
        @NonNull List<DiskEntry> placedDisks, @NonNull List<BootFile> placedBoots,
        int done, int total, int appUid, @Nullable AppleMacPreparationResult preparation
    ) throws IOException {
        if (guest == Guest.MACOS && preparation == null)
            throw new IOException("macOS import has no verified 4 GiB GPT/APFS preparation result");
        if (guest != Guest.MACOS && preparation != null)
            throw new IOException("macOS preparation result cannot bind another Apple guest");
        var expected = members(guest);
        int required = expected.size() + 1;
        if (done != required || total != required || placedDisks.size() != expected.size()
            || placedBoots.size() != 1 || appUid <= 0 || !matchesVm(guest, vm, preparation != null))
            throw new IOException("Apple import completion or device profile is incomplete");
        if (vm.getName() == null || vm.getName().isEmpty())
            throw new IOException("Imported Apple VM has no name");
        // Parsing the actual UUID also refuses a malformed daemon configuration.
        vm.getId();
        var disks = sourceDisks(guest, placedDisks);
        String directory = null;
        for (var spec : expected) {
            var disk = disks.get(spec.archive);
            if (preparation == null && !disk.sha256Verified)
                throw new IOException("Apple import disk identity was not verified");
            var parent = deviceParent(disk.ref.path);
            if (directory == null) directory = parent;
            else if (!directory.equals(parent))
                throw new IOException("Apple import disks do not share their actual import directory");
        }
        var firmware = placedBoots.get(0);
        if (!matchesFirmware(guest, firmware) || !firmware.sha256Verified
            || !deviceParent(firmware.path).equals(directory + "/boot"))
            throw new IOException("Apple import firmware identity or placement was not verified");
        var uefi = vm.item.lookup("boot.uefi.firmware");
        if (!uefi.is(DataItem.Type.STRING) || !firmware.path.equals(uefi.asString()))
            throw new IOException("Imported Apple VM firmware differs from its completed import");
        var attached = vm.item.opt("disks", DataItem.newArray());
        int attachedCount = guest == Guest.MACOS ? 2 : 1;
        if (!attached.is(DataItem.Type.ARRAY) || attached.asArray().size() != attachedCount)
            throw new IOException("Imported Apple VM disk slots differ from its completed import");
        for (var spec : expected) {
            if (spec.attached && !disks.get(spec.archive).ref.path.equals(
                attached.get(spec.index).optString("path", "")))
                throw new IOException("Imported Apple VM disk path differs from its completed import");
        }
        if (preparation != null)
            preparation.requireMatches(vm.getId(), directory, disks.get("disks/boot.img"),
                disks.get("disks/data-store.img"));
        var simplefb = vm.item.lookup("screens.simplefb");
        if (guest == Guest.MACOS && !simplefb.is(DataItem.Type.OBJECT))
            throw new IOException("Imported macOS VM has no SimpleFB screen binding");
        var options = options(guest, directory, disks, appUid);
        if (guest == Guest.IPADOS) {
            // The Edge scheduler needs both E and P psets: selecting only host cores
            // 2-5 produced PPPP and failed its QoS parallelism assertion at launchd.
            vm.item.set("memory_mb", 4096);
            vm.item.set("cpu_affinity", "0=2:1=3:2=6:3=7");
            vm.item.set("cpu_capacity", "0=792,1=792,2=1024,3=1024");
            vm.item.set("cpu_clusters", "0-1;2-3");
            vm.item.set("cpu_topology_auto", false);
        } else {
            // An independent native binding avoids crosvm's invalid "#boot" fallback
            // service name. The completed native preparation supplies the 4 GiB boot image.
            vm.item.set("memory_mb", 4096);
            simplefb.set("exporter", "native");
        }
        vm.item.set("extra_options", options);
        vm.item.set("auto_up", false);
    }

    @NonNull
    static String deviceParent(@Nullable String path) throws IOException {
        // These are Android device paths, even when tests run on a Windows build host.
        if (path == null || !path.startsWith("/") || path.endsWith("/")
            || path.indexOf('\0') >= 0 || path.lastIndexOf('/') <= 0)
            throw new IOException("Apple import did not supply an absolute device file path");
        return path.substring(0, path.lastIndexOf('/'));
    }

    @NonNull
    private static List<String> options(
        Guest guest, String directory, Map<String, DiskEntry> disks, int appUid
    ) throws IOException {
        var options = new ArrayList<String>();
        options.add("--dump-device-tree-blob");
        options.add(directory + "/runtime.dtb");
        if (guest == Guest.MACOS) {
            options.addAll(List.of("--mbi-spis", "64", "--virtio-mmio-gpu",
                "--pre-alloc", "media-host-mb=8"));
        } else {
            for (var archive : List.of("disks/os.img", "disks/systemos.img", "disks/data-store.img")) {
                var disk = disks.get(archive);
                // Commas delimit the crosvm block options and cannot name a backing file.
                if (disk.ref.path.contains(","))
                    throw new IOException("Apple disk path contains the block-option delimiter");
                options.add("--virtio-mmio-block");
                // Android shared-storage files cannot supply the file-lock operation.
                options.add(disk.ref.path + (disk.ref.readonly ? ",ro=true" : "") + ",lock=false");
            }
            options.addAll(List.of("--virtio-mmio-input", "--virtio-mmio-net", "--virtio-mmio-gpu",
                "--pre-alloc", "drm-host-mb=8,media-host-mb=64", "--battery", "type=goldfish"));
        }
        options.add("--virtio-snd");
        options.add("backend=aaudio,capture=true,num_output_devices=1,num_input_devices=1,uid=" + appUid);
        options.add("--virtio-mmio-snd");
        options.add("--virtio-media");
        // The default MediaCodec backend uses the existing Android codec service.
        options.add("kind=decoder,uid=" + appUid);
        if (guest == Guest.MACOS) {
            options.add("--virtio-media");
            options.add("kind=encoder,uid=" + appUid);
        }
        options.add("--virtio-mmio-media");
        return options;
    }
}
