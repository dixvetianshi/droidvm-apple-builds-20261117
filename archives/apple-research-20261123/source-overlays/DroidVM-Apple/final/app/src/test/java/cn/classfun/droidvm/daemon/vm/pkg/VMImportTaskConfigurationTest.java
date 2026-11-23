// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm.pkg;

import static cn.classfun.droidvm.lib.pkg.AppleGuestImportProfileTest.verifiedManifest;
import static cn.classfun.droidvm.lib.pkg.AppleMacPreparationResultTest.nativeFacts;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile;
import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile.Guest;
import cn.classfun.droidvm.lib.pkg.AppleMacPreparationResult;
import cn.classfun.droidvm.lib.pkg.BootFile;
import cn.classfun.droidvm.lib.pkg.DiskEntry;
import cn.classfun.droidvm.lib.pkg.PackageManifest;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.vm.CpuPlacementPlan;
import cn.classfun.droidvm.lib.store.vm.VMConfig;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

public final class VMImportTaskConfigurationTest {
    /** No I/O is performed here; retain Android File paths on the Windows test host. */
    private static final class AndroidFile extends File {
        private static final long serialVersionUID = 1L;
        private final String devicePath;

        AndroidFile(String devicePath) {
            super(devicePath);
            this.devicePath = devicePath;
        }

        @Override public String getPath() { return devicePath; }
        @Override public String getAbsolutePath() { return devicePath; }
    }

    private static VMConfig sourceConfig(PackageManifest manifest) throws Exception {
        var slots = DataItem.newArray();
        for (var disk : manifest.disks) {
            if (!disk.attached) continue;
            var slot = DataItem.newObject();
            slot.set("path", disk.ref.path);
            slot.set("readonly", disk.ref.readonly);
            slot.set("bus", disk.ref.bus);
            slots.append(slot);
        }
        manifest.vm.item.set("disks", slots);
        manifest.vm.item.set("boot", Map.of("protocol", "uefi", "uefi", Map.of(
            "firmware", manifest.boots.get(0).path, "vars_enabled", false, "vars", "")));
        return new VMConfig(manifest.vm.toJson());
    }

    private static ArrayList<DiskEntry> placedDisks(PackageManifest manifest, String directory) {
        for (var disk : manifest.disks) {
            disk.target = new AndroidFile(directory + "/" + disk.name);
            disk.sha256Verified = true;
        }
        return new ArrayList<>(manifest.disks);
    }

    private static ArrayList<BootFile> placedBoots(PackageManifest manifest, String directory) {
        for (var boot : manifest.boots) {
            boot.target = new AndroidFile(directory + "/boot/" + boot.name);
            boot.sha256Verified = true;
        }
        return new ArrayList<>(manifest.boots);
    }

    private static List<String> options(VMConfig vm) {
        return vm.item.get("extra_options").asArray().stream()
            .map(DataItem::asString).collect(Collectors.toList());
    }

    @Test
    public void originalIpadRecipeUsesActualTargetsFourGiBEeppAndCurrentUidBeforeRegistration()
        throws Exception {
        var manifest = verifiedManifest(Guest.IPADOS);
        var guest = AppleGuestImportProfile.identify(manifest);
        assertEquals(Guest.IPADOS, guest);
        var vm = sourceConfig(manifest);
        var id = UUID.randomUUID();
        vm.setId(id);
        vm.setName("Chosen iPad name");
        vm.item.set(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, AppRuntimeIdentity.LEGACY_GPU_CGROUP_PATH);
        var screens = new DataItem(vm.item.get("screens").toJson());
        var networks = new DataItem(vm.item.get("networks").toJsonArray());
        String directory = "/storage/emulated/0/Apple6 root/iPad renamed (2)";
        var disks = placedDisks(manifest, directory);
        var boots = placedBoots(manifest, directory);
        disks.get(1).target = new AndroidFile(directory + "/os_1.img");
        disks.get(3).target = new AndroidFile(directory + "/data-store_2.img");
        assertEquals(5120, vm.item.optLong("memory_mb", 0));
        assertEquals("0=2:1=3:2=4:3=5", vm.item.optString("cpu_affinity", ""));
        assertTrue(disks.stream().allMatch(disk -> disk.ref.path.startsWith("/old/")));
        assertTrue(boots.get(0).path.startsWith("/old/"));

        assertNull(VMImportTask.completeConfiguration(guest, vm, disks, boots, 5, 12345, null));

        assertEquals(id, vm.getId());
        assertEquals("Chosen iPad name", vm.getName());
        assertEquals(networks, vm.item.get("networks"));
        assertEquals(screens, vm.item.get("screens"));
        assertEquals(4, vm.item.optLong("cpu_count", 0));
        assertEquals(4096, vm.item.optLong("memory_mb", 0));
        assertEquals("0=2:1=3:2=6:3=7", vm.item.optString("cpu_affinity", ""));
        assertEquals("0=792,1=792,2=1024,3=1024", vm.item.optString("cpu_capacity", ""));
        assertEquals("0-1;2-3", vm.item.optString("cpu_clusters", ""));
        assertFalse(vm.item.optBoolean("cpu_topology_auto", true));
        assertFalse(vm.item.optBoolean("auto_up", true));
        assertEquals(CpuPlacementPlan.DEFAULT_GPU_CGROUP_PATH,
            vm.item.optString(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, ""));
        assertEquals(1, vm.item.get("disks").asArray().size());
        assertEquals(directory + "/droidvm-disk.img", vm.item.get("disks").get(0).optString("path", ""));
        assertEquals(directory + "/boot/edk2-virtio-gpu.fd", vm.item.lookup("boot.uefi.firmware").asString());
        for (var disk : disks) assertEquals(disk.target.getPath(), disk.ref.path);
        assertEquals(boots.get(0).target.getPath(), boots.get(0).path);
        var opts = options(vm);
        assertEquals(3, opts.stream().filter("--virtio-mmio-block"::equals).count());
        assertTrue(opts.contains(directory + "/os_1.img,ro=true,lock=false"));
        assertTrue(opts.contains(directory + "/systemos.img,ro=true,lock=false"));
        assertTrue(opts.contains(directory + "/data-store_2.img,lock=false"));
        assertTrue(opts.contains(directory + "/runtime.dtb"));
        assertTrue(opts.contains("backend=aaudio,capture=true,num_output_devices=1,num_input_devices=1,uid=12345"));
        assertTrue(opts.contains("kind=decoder,uid=12345"));
        assertFalse(opts.stream().anyMatch(value -> value.contains("10652") || value.contains("/old/")));
        assertEquals(5120, manifest.vm.item.optLong("memory_mb", 0));
    }

    @Test
    public void preparedMacUsesItsNewRawTargetFourGiBAndNativeSimplefbBeforeRegistration()
        throws Exception {
        var manifest = verifiedManifest(Guest.MACOS);
        var guest = AppleGuestImportProfile.identify(manifest);
        assertEquals(Guest.MACOS, guest);
        var vm = sourceConfig(manifest);
        var id = UUID.randomUUID();
        vm.setId(id);
        vm.setName("Chosen Mac name");
        var gpu = new DataItem(vm.item.lookup("screens.gpu-0").toJson());
        var simplefb = new DataItem(vm.item.lookup("screens.simplefb").toJson());
        simplefb.set("exporter", "native");
        String directory = "/storage/emulated/0/Apple6 root/macOS (1)";
        var disks = placedDisks(manifest, directory);
        var boots = placedBoots(manifest, directory);
        disks.get(0).sha256Verified = false;
        disks.get(1).sha256Verified = false;
        disks.get(1).target = new AndroidFile(directory + "/data-pcie.img");
        var preparation = nativeFacts(directory);
        assertEquals(5120, vm.item.optLong("memory_mb", 0));
        assertEquals("/old/data-store.img", disks.get(1).ref.path);

        var completed = VMImportTask.completeConfiguration(guest, vm, disks, boots, 3, 12346, preparation);

        assertEquals(id, vm.getId());
        assertEquals("Chosen Mac name", vm.getName());
        assertEquals(4096, vm.item.optLong("memory_mb", 0));
        assertEquals(8, vm.item.optLong("cpu_count", 0));
        assertEquals("0=0:1=1:2=2:3=3:4=4:5=5:6=6:7=7", vm.item.optString("cpu_affinity", ""));
        assertEquals("0-5;6-7", vm.item.optString("cpu_clusters", ""));
        assertFalse(vm.item.optBoolean("auto_up", true));
        assertEquals(gpu, vm.item.lookup("screens.gpu-0"));
        assertEquals(simplefb, vm.item.lookup("screens.simplefb"));
        assertEquals(directory + "/boot.img", disks.get(0).ref.path);
        assertEquals(directory + "/data-pcie.img", disks.get(1).ref.path);
        assertEquals(directory + "/data-pcie.img", vm.item.get("disks").get(1).optString("path", ""));
        assertEquals(directory + "/boot/edk2-macos.fd", vm.item.lookup("boot.uefi.firmware").asString());
        assertEquals(51541188608L, disks.get(1).size);
        assertEquals("290221956ea4c2d42504a2885427e60e01be86e144b225b777b54263a916ddd0", disks.get(1).sha256);
        assertFalse(disks.get(0).sha256Verified);
        assertFalse(disks.get(1).sha256Verified);
        var opts = options(vm);
        assertTrue(opts.contains(directory + "/runtime.dtb"));
        assertTrue(opts.contains("kind=decoder,uid=12346"));
        assertEquals(2, opts.stream().filter("--virtio-media"::equals).count());
        assertTrue(opts.contains("--virtio-mmio-media"));
        assertTrue(opts.contains("kind=encoder,uid=12346"));
        assertFalse(opts.contains("--virtio-mmio-block"));
        assertFalse(opts.stream().anyMatch(value -> value.contains("10652") || value.contains("/old/")));
        var facts = completed.toJson(id);
        assertEquals(id.toString(), facts.getString("vm_id"));
        assertEquals(directory + "/data-store.img", facts.getString("source_store_path"));
        assertEquals(directory + "/data-pcie.img", facts.getString("derived_disk_path"));
        assertEquals(AppleMacPreparationResult.DISK_BYTES, facts.getLong("derived_disk_bytes"));
    }

    @Test
    public void ordinaryImportRetainsCustomGpuCpuMemoryAndRuntimeChoices() throws Exception {
        var manifest = verifiedManifest(Guest.IPADOS);
        manifest.vm.setName("My Linux VM");
        manifest.vm.item.set("memory_mb", 7168);
        manifest.vm.item.set("cpu_count", 6);
        manifest.vm.item.set("cpu_affinity", "0=1-2:1=3:2=4:3=5:4=6:5=7");
        manifest.vm.item.set("cpu_capacity", "0=600,1=600,2=800,3=800,4=1024,5=1024");
        manifest.vm.item.set("cpu_clusters", "0-1;2-3;4-5");
        manifest.vm.item.set("cpu_topology_auto", false);
        manifest.vm.item.set("screens", Map.of("gpu-0", Map.of("enabled", true,
            "exporter", "native", "input_enabled", false, "width", 1440, "height", 900)));
        manifest.vm.item.set(CpuPlacementPlan.KEY_GPU_CGROUP, true);
        manifest.vm.item.set(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, "/dev/cpuset/my_vm_gpu");
        manifest.vm.item.set(CpuPlacementPlan.KEY_GPU_CGROUP_CPUS, "4-5");
        manifest.vm.item.set("extra_options", List.of("--my-option", "uid=10652"));
        var guest = AppleGuestImportProfile.identify(manifest);
        assertNull(guest);
        var vm = sourceConfig(manifest);
        var settings = new DataItem(vm.item.toJson());
        settings.remove("disks");
        settings.remove("boot");
        String directory = "/storage/emulated/0/Ordinary VM";
        var disks = placedDisks(manifest, directory);
        var boots = placedBoots(manifest, directory);

        assertNull(VMImportTask.completeConfiguration(guest, vm, disks, boots, 5, -1, null));

        var saved = new DataItem(vm.item.toJson());
        saved.remove("disks");
        saved.remove("boot");
        assertEquals(settings, saved);
        assertEquals(7168, vm.item.optLong("memory_mb", 0));
        assertEquals(6, vm.item.optLong("cpu_count", 0));
        assertTrue(vm.item.optBoolean("auto_up", false));
        assertEquals("/dev/cpuset/my_vm_gpu", vm.item.optString(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, ""));
        assertEquals(directory + "/droidvm-disk.img", vm.item.get("disks").get(0).optString("path", ""));
        assertEquals(directory + "/boot/edk2-virtio-gpu.fd", vm.item.lookup("boot.uefi.firmware").asString());
    }

    @Test
    public void incompleteOrUnverifiedAppleCopyCannotCompleteBeforeRegistration() throws Exception {
        for (int failure = 0; failure < 4; failure++) {
            var manifest = verifiedManifest(Guest.IPADOS);
            var guest = AppleGuestImportProfile.identify(manifest);
            var vm = sourceConfig(manifest);
            vm.item.set(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, AppRuntimeIdentity.LEGACY_GPU_CGROUP_PATH);
            var originalOptions = new DataItem(vm.item.get("extra_options").toJsonArray());
            var disks = placedDisks(manifest, "/storage/emulated/0/Incomplete iPad");
            var boots = placedBoots(manifest, "/storage/emulated/0/Incomplete iPad");
            int total = 5;
            switch (failure) {
                case 0: total = 4; break;
                case 1: disks.get(1).sha256Verified = false; break;
                case 2: boots.get(0).sha256Verified = false; break;
                case 3: disks.remove(1); break;
                default: throw new AssertionError();
            }
            final int totalItems = total;

            assertThrows(IOException.class, () -> VMImportTask.completeConfiguration(
                guest, vm, disks, boots, totalItems, 12345, null));

            assertEquals(originalOptions, vm.item.get("extra_options"));
            assertEquals(5120, vm.item.optLong("memory_mb", 0));
            assertEquals("0=2:1=3:2=4:3=5", vm.item.optString("cpu_affinity", ""));
            assertTrue(vm.item.optBoolean("auto_up", false));
            assertEquals(AppRuntimeIdentity.LEGACY_GPU_CGROUP_PATH,
                vm.item.optString(CpuPlacementPlan.KEY_GPU_CGROUP_PATH, ""));
        }
    }
}
