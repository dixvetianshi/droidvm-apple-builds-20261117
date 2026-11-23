// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile.Guest;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.disk.DiskBus;
import cn.classfun.droidvm.lib.store.vm.VMConfig;
import cn.classfun.droidvm.ui.disk.create.DiskFormat;

public final class AppleGuestImportProfileTest {
    /** Values from the two packed-and-verified r242 manifests, not VM display names. */
    public static PackageManifest verifiedManifest(Guest guest) {
        var manifest = new PackageManifest();
        manifest.manifestVersion = guest == Guest.MACOS ? 1 : 2;
        manifest.format = "vmpkg";
        manifest.appVersion = "0.0.6.r242.g3348830";
        manifest.appVersionCode = 2720;
        manifest.appBuildType = "release";
        var vm = manifest.vm;
        vm.setName("User renamed this VM");
        vm.item.set("cpu_count", guest == Guest.MACOS ? 8 : 4);
        vm.item.set("memory_mb", 5120);
        vm.item.set("cpu_affinity", guest == Guest.MACOS ? "0=0:1=1:2=2:3=3:4=4:5=5:6=6:7=7" : "0=2:1=3:2=4:3=5");
        vm.item.set("cpu_topology_auto", guest != Guest.MACOS);
        vm.item.set("cpu_capacity", guest == Guest.MACOS ? "0=792,1=792,2=792,3=792,4=792,5=792,6=1024,7=1024" : "");
        vm.item.set("cpu_clusters", guest == Guest.MACOS ? "0-5;6-7" : "");
        vm.item.set("backend", "crosvm");
        vm.item.set("hypervisor", "gunyah");
        vm.item.set("protected_vm", "pseudo_unprotected");
        vm.item.set("virtio_transport", "pci");
        vm.item.set("hugepages", true);
        vm.item.set("auto_up", true);
        vm.item.set("extra_options", List.of("--dump-device-tree-blob", "/old/runtime.dtb", "uid=10652"));
        vm.item.set("networks", List.of(Map.of("network_id", "chosen-network", "mac_address", "02:00:00:aa:bb:01")));
        vm.item.set("screens", Map.of(
            "simplefb", Map.of("enabled", guest == Guest.MACOS, "exporter", "none",
                "width", guest == Guest.MACOS ? 1920 : 1024, "height", guest == Guest.MACOS ? 1080 : 1366,
                "input_enabled", false, "transport_cap", "gpu", "retained_setting", "kept"),
            "gpu-0", Map.of("enabled", true, "exporter", "native", "input_enabled", true, "retained_setting", "kept")));
        if (guest == Guest.MACOS) {
            manifest.disks.add(disk("disks/boot.img", 402653184L,
                "991125c52d9e1becee16a39c670f8573ed8c0ddb64b06c7c578e7083973c45d1", 0, false, true));
            manifest.disks.add(disk("disks/data-store.img", 51541188608L,
                "290221956ea4c2d42504a2885427e60e01be86e144b225b777b54263a916ddd0", 1, false, true));
        } else {
            manifest.disks.add(disk("disks/droidvm-disk.img", 335544320L,
                "5d62008d8f5b5e5e4a1ad952a1520f37a9aa4f35e00b6853770dba4be243709c", 0, true, true));
            manifest.disks.add(disk("disks/os.img", 9613344768L,
                "8a12cdad43f8f0d33dadcf01a800a560222baf40c05f71374c460ba57ba3a739", -1, true, false));
            manifest.disks.add(disk("disks/systemos.img", 6016729088L,
                "d5b4873d35c85f96eaafaa31c59602b485afe33b5067eff1af67ba31204cdb4a", -1, true, false));
            manifest.disks.add(disk("disks/data-store.img", 17179869184L,
                "8f2aaec406990e150b5c701b25fd231338a92b8063555a0734fd30d8494a8967", -1, false, false));
        }
        var boot = new BootFile();
        boot.archivePath = guest == Guest.MACOS ? "boots/edk2-macos.fd" : "boots/edk2-virtio-gpu.fd";
        boot.name = boot.archivePath.substring(6);
        boot.path = "/old/boot/" + boot.name;
        boot.kind = "uefi";
        boot.size = 4194304L;
        boot.sha256 = guest == Guest.MACOS
            ? "124ca25827ddb328a666dbac8698e079f47f7208c2dfa582d07cc33fd0a24141"
            : "1d68346fa2df7c4775b3ca06fb7ac3992b7160600669ea3d8a560eab3dd360a2";
        manifest.boots.add(boot);
        return manifest;
    }

    private static DiskEntry disk(String archive, long size, String sha256,
                                  int index, boolean readonly, boolean attached) {
        var ref = new DiskRef(index, "/old/" + archive.substring(6));
        ref.readonly = readonly;
        ref.bus = DiskBus.VIRTIO;
        var disk = new DiskEntry(ref);
        disk.archivePath = archive;
        disk.name = archive.substring(6);
        disk.format = DiskFormat.RAW;
        disk.size = size;
        disk.sha256 = sha256;
        disk.attached = attached;
        return disk;
    }

    static void completeImport(PackageManifest manifest, String directory) {
        var attached = new ArrayList<DataItem>();
        for (var disk : manifest.disks) {
            disk.ref.path = directory + "/" + disk.name;
            disk.sha256Verified = true;
            if (disk.attached) {
                var slot = DataItem.newObject();
                slot.set("path", disk.ref.path);
                slot.set("readonly", disk.ref.readonly);
                slot.set("bus", "virtio");
                attached.add(slot);
            }
        }
        var firmware = manifest.boots.get(0);
        firmware.path = directory + "/boot/" + firmware.name;
        firmware.sha256Verified = true;
        manifest.vm.item.set("disks", attached);
        manifest.vm.item.set("boot", Map.of("protocol", "uefi", "uefi",
            Map.of("firmware", firmware.path, "vars_enabled", false, "vars", "")));
    }

    private static AppleMacPreparationResult completePreparedMacImport(
        PackageManifest manifest, String directory
    ) throws Exception {
        completeImport(manifest, directory);
        var id = UUID.randomUUID();
        manifest.vm.setId(id);
        manifest.vm.item.set("memory_mb", 4096);
        manifest.vm.item.set("auto_up", false);
        manifest.disks.get(0).sha256Verified = false;
        manifest.disks.get(1).sha256Verified = false;
        manifest.disks.get(1).ref.path = directory + "/data-pcie.img";
        manifest.vm.item.get("disks").get(1).set("path", directory + "/data-pcie.img");
        return AppleMacPreparationResultTest.nativeFacts(directory).bindToVM(id);
    }

    private static List<String> options(VMConfig vm) {
        return vm.item.get("extra_options").asArray().stream()
            .map(DataItem::asString).collect(Collectors.toList());
    }

    @Test
    public void exactImagesAreIdentifiedEvenAfterTheVmIsRenamed() {
        assertEquals(Guest.MACOS, AppleGuestImportProfile.identify(verifiedManifest(Guest.MACOS)));
        assertEquals(Guest.IPADOS, AppleGuestImportProfile.identify(verifiedManifest(Guest.IPADOS)));
    }

    @Test
    public void knownOldIpadBootIsRefusedEvenAfterMetadataOrVmNameEdits() throws Exception {
        var manifest = verifiedManifest(Guest.IPADOS);
        manifest.disks.get(0).sha256 = "8bedfd8dc7ffde37d35d8c49816d404f7c27deedb85d460534c365324027638f";
        assertNull(AppleGuestImportProfile.identify(manifest));
        var error = assertThrows(IOException.class, () -> AppleGuestImportProfile.requireSupportedImport(manifest));
        assertTrue(error.getMessage().contains("修复版 iPadOS .vmpkg"));
        manifest.vm.setName("My renamed VM");
        manifest.appVersion = "different exporter";
        manifest.appVersionCode = 1;
        manifest.disks.get(1).sha256 = "0".repeat(64);
        assertThrows(IOException.class, () -> AppleGuestImportProfile.requireSupportedImport(manifest));
    }

    @Test
    public void unknownOrdinaryPackagesAndMacRetainTheirImportRoute() throws Exception {
        var ordinary = verifiedManifest(Guest.IPADOS);
        ordinary.disks.get(0).sha256 = "a".repeat(64);
        ordinary.vm.item.set("backend", "ordinary");
        assertNull(AppleGuestImportProfile.identify(ordinary));
        AppleGuestImportProfile.requireSupportedImport(ordinary);
        var mac = verifiedManifest(Guest.MACOS);
        AppleGuestImportProfile.requireSupportedImport(mac);
        assertEquals(Guest.MACOS, AppleGuestImportProfile.identify(mac));
    }

    @Test
    public void floorRecognitionStillRequiresEveryMemberFirmwareAndSourceHeader() throws Exception {
        for (int failure = 0; failure < 5; failure++) {
            var manifest = verifiedManifest(Guest.IPADOS);
            switch (failure) {
                case 0: manifest.disks.get(1).sha256 = "0".repeat(64); break;
                case 1: manifest.disks.get(2).size++; break;
                case 2: manifest.boots.get(0).sha256 = "0".repeat(64); break;
                case 3: manifest.appVersionCode++; break;
                case 4: manifest.vm.item.set("protected_vm", "different"); break;
                default: throw new AssertionError();
            }
            assertNull(AppleGuestImportProfile.identify(manifest));
        }
    }

    @Test
    public void newFourGiBIpadRecipeAndOriginalFiveGiBPackageBothRetainTheirIdentity() {
        var manifest = verifiedManifest(Guest.IPADOS);
        assertEquals(Guest.IPADOS, AppleGuestImportProfile.identify(manifest));
        manifest.vm.item.set("memory_mb", 4096);
        assertEquals(Guest.IPADOS, AppleGuestImportProfile.identify(manifest));
        manifest.vm.item.set("memory_mb", 2048);
        assertNull(AppleGuestImportProfile.identify(manifest));
        manifest = verifiedManifest(Guest.MACOS);
        manifest.vm.item.set("memory_mb", 4096);
        // The old fixed 5 GiB macOS boot disk is not the new separately adapted disk.
        assertNull(AppleGuestImportProfile.identify(manifest));
    }

    @Test
    public void matchingDisplayNameDoesNotOwnDifferentOrUncheckedImages() {
        var manifest = verifiedManifest(Guest.IPADOS);
        manifest.vm.setName("iPadOS 27.0.1 (DroidVM)");
        manifest.disks.get(1).sha256 = "";
        assertNull(AppleGuestImportProfile.identify(manifest));
        manifest = verifiedManifest(Guest.MACOS);
        manifest.disks.get(0).sha256 = "0".repeat(64);
        assertNull(AppleGuestImportProfile.identify(manifest));
        manifest = verifiedManifest(Guest.MACOS);
        manifest.vm.item.set("cpu_count", 4);
        assertNull(AppleGuestImportProfile.identify(manifest));
    }

    @Test
    public void ipadBindsAllThreeMmioDisksToActualPathsAndCurrentUid() throws Exception {
        var manifest = verifiedManifest(Guest.IPADOS);
        String directory = "/storage/emulated/0/Chosen folder/iPad renamed (2)";
        completeImport(manifest, directory);
        var id = UUID.randomUUID();
        manifest.vm.setId(id);
        var name = manifest.vm.getName();
        var networks = new DataItem(manifest.vm.item.get("networks").toJsonArray());
        var boot = new DataItem(manifest.vm.item.get("boot").toJson());
        var disks = new DataItem(manifest.vm.item.get("disks").toJsonArray());
        var screens = new DataItem(manifest.vm.item.get("screens").toJson());
        AppleGuestImportProfile.bind(Guest.IPADOS, manifest.vm, manifest.disks,
            manifest.boots, 5, 5, 12123);
        var opts = options(manifest.vm);
        assertTrue(opts.contains(directory + "/runtime.dtb"));
        assertTrue(opts.contains(directory + "/os.img,ro=true,lock=false"));
        assertTrue(opts.contains(directory + "/systemos.img,ro=true,lock=false"));
        assertTrue(opts.contains(directory + "/data-store.img,lock=false"));
        assertEquals(3, opts.stream().filter("--virtio-mmio-block"::equals).count());
        assertTrue(opts.contains("--virtio-mmio-input"));
        assertTrue(opts.contains("--virtio-mmio-net"));
        assertTrue(opts.contains("--virtio-mmio-gpu"));
        assertTrue(opts.contains("--virtio-mmio-snd"));
        assertTrue(opts.contains("--virtio-mmio-media"));
        assertTrue(opts.contains("backend=aaudio,capture=true,num_output_devices=1,num_input_devices=1,uid=12123"));
        assertTrue(opts.contains("kind=decoder,uid=12123"));
        assertFalse(opts.stream().anyMatch(value -> value.contains("10652") || value.startsWith("/old/")));
        assertEquals(id, manifest.vm.getId());
        assertEquals(name, manifest.vm.getName());
        assertEquals(networks, manifest.vm.item.get("networks"));
        assertEquals(boot, manifest.vm.item.get("boot"));
        assertEquals(disks, manifest.vm.item.get("disks"));
        assertEquals(screens, manifest.vm.item.get("screens"));
        assertEquals(4096, manifest.vm.item.optLong("memory_mb", 0));
        assertEquals("0=2:1=3:2=6:3=7", manifest.vm.item.optString("cpu_affinity", ""));
        assertEquals("0=792,1=792,2=1024,3=1024", manifest.vm.item.optString("cpu_capacity", ""));
        assertEquals("0-1;2-3", manifest.vm.item.optString("cpu_clusters", ""));
        assertFalse(manifest.vm.item.optBoolean("cpu_topology_auto", true));
        assertFalse(manifest.vm.item.optBoolean("auto_up", true));
    }

    @Test
    public void preparedMacBindsItsFourGiBPciModelAndActualDtbPath() throws Exception {
        var manifest = verifiedManifest(Guest.MACOS);
        var preparation = completePreparedMacImport(manifest,
            "/storage/emulated/0/Other folder/macOS (1)");
        var gpu = new DataItem(manifest.vm.item.lookup("screens.gpu-0").toJson());
        var simplefbBefore = new DataItem(manifest.vm.item.lookup("screens.simplefb").toJson());
        simplefbBefore.set("exporter", "native");
        AppleGuestImportProfile.bind(Guest.MACOS, manifest.vm, manifest.disks,
            manifest.boots, 3, 3, 12124, preparation);
        var opts = options(manifest.vm);
        assertEquals("64", opts.get(opts.indexOf("--mbi-spis") + 1));
        assertTrue(opts.contains("/storage/emulated/0/Other folder/macOS (1)/runtime.dtb"));
        assertTrue(opts.contains("kind=decoder,uid=12124"));
        assertEquals(2, opts.stream().filter("--virtio-media"::equals).count());
        assertTrue(opts.contains("--virtio-mmio-media"));
        assertTrue(opts.contains("kind=encoder,uid=12124"));
        assertFalse(opts.contains("--virtio-mmio-block"));
        assertEquals(8, manifest.vm.item.optLong("cpu_count", 0));
        assertEquals(4096, manifest.vm.item.optLong("memory_mb", 0));
        assertEquals("/storage/emulated/0/Other folder/macOS (1)/data-pcie.img",
            manifest.vm.item.get("disks").get(1).optString("path", ""));
        // Source archive provenance remains intact; modified copies do not claim its digest.
        assertEquals(51541188608L, manifest.disks.get(1).size);
        assertFalse(manifest.disks.get(0).sha256Verified);
        assertFalse(manifest.disks.get(1).sha256Verified);
        assertEquals("0-5;6-7", manifest.vm.item.optString("cpu_clusters", ""));
        assertEquals("0=0:1=1:2=2:3=3:4=4:5=5:6=6:7=7", manifest.vm.item.optString("cpu_affinity", ""));
        assertEquals(gpu, manifest.vm.item.lookup("screens.gpu-0"));
        assertEquals(simplefbBefore, manifest.vm.item.lookup("screens.simplefb"));
    }

    @Test
    public void originalMacSourceCannotBindWithoutNativePreparationFacts() throws Exception {
        var manifest = verifiedManifest(Guest.MACOS);
        completeImport(manifest, "/storage/emulated/0/macOS");
        var before = new DataItem(manifest.vm.item.toJson());
        assertThrows(IOException.class, () -> AppleGuestImportProfile.bind(Guest.MACOS,
            manifest.vm, manifest.disks, manifest.boots, 3, 3, 12124));
        assertEquals(before, manifest.vm.item);
    }

    @Test
    public void incompleteOrUnverifiedNativeResultCannotMutateSavedParameters() throws Exception {
        var manifest = verifiedManifest(Guest.IPADOS);
        completeImport(manifest, "/storage/emulated/0/iPad");
        var before = new DataItem(manifest.vm.item.get("extra_options").toJsonArray());
        assertThrows(IOException.class, () -> AppleGuestImportProfile.bind(Guest.IPADOS,
            manifest.vm, manifest.disks, manifest.boots, 4, 5, 12123));
        assertEquals(before, manifest.vm.item.get("extra_options"));
        manifest.disks.get(1).sha256Verified = false;
        assertThrows(IOException.class, () -> AppleGuestImportProfile.bind(Guest.IPADOS,
            manifest.vm, manifest.disks, manifest.boots, 5, 5, 12123));
        assertEquals(before, manifest.vm.item.get("extra_options"));
        assertTrue(manifest.vm.item.optBoolean("auto_up", false));
    }

    @Test
    public void anotherVmsPathsCannotBeMistakenForThisNativeImport() throws Exception {
        var manifest = verifiedManifest(Guest.MACOS);
        var preparation = completePreparedMacImport(manifest, "/storage/emulated/0/macOS");
        manifest.vm.item.get("disks").get(0).set("path", "/storage/emulated/0/anotherVM/boot.img");
        assertThrows(IOException.class, () -> AppleGuestImportProfile.bind(Guest.MACOS,
            manifest.vm, manifest.disks, manifest.boots, 3, 3, 12123, preparation));
    }
}
