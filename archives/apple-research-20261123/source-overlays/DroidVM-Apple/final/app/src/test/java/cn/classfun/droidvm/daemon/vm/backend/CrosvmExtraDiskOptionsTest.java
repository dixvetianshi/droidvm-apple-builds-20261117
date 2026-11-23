// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm.backend;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.util.List;

public final class CrosvmExtraDiskOptionsTest {
    @Test
    public void oldIpadStoreGetsAllThreeMmioDisksWithoutReimportingOrChangingTheirPaths() {
        String directory = "/storage/emulated/0/Chosen folder/iPadOS (1)";
        var saved = List.of("--dump-device-tree-blob", directory + "/runtime.dtb",
            "--virtio-mmio-block", directory + "/os.img,ro=true",
            "--virtio-mmio-block", directory + "/systemos.img,ro=true",
            "--virtio-mmio-block", directory + "/data-store.img",
            "--virtio-media", "kind=decoder,uid=12123");
        var expected = List.of("--dump-device-tree-blob", directory + "/runtime.dtb",
            "--virtio-mmio-block", directory + "/os.img,ro=true,lock=false",
            "--virtio-mmio-block", directory + "/systemos.img,ro=true,lock=false",
            "--virtio-mmio-block", directory + "/data-store.img,lock=false",
            "--virtio-media", "kind=decoder,uid=12123");
        var normalized = CrosvmExtraDiskOptions.forAndroidSharedStorage(saved);
        assertEquals(expected, normalized);
        assertEquals(expected, CrosvmExtraDiskOptions.forAndroidSharedStorage(normalized));
        assertFalse(saved.get(3).contains("lock="));
    }

    @Test
    public void bothArgFormsReplaceLockTrueAndKeepReadonlyAndUnknownDiskOptions() {
        var arguments = List.of("--virtio-mmio-block", "/disk.img,ro=true,lock=true,sparse=false",
            "--virtio-mmio-block=/other disk.img,lock=true,ro=false,custom=kept");
        assertEquals(List.of("--virtio-mmio-block", "/disk.img,ro=true,lock=false,sparse=false",
            "--virtio-mmio-block=/other disk.img,lock=false,ro=false,custom=kept"),
            CrosvmExtraDiskOptions.forAndroidSharedStorage(arguments));
    }

    @Test
    public void existingLockFalseRemainsUnchangedAndDuplicatedLockKeysBecomeOne() {
        var arguments = List.of("--virtio-mmio-block", "/disk.img,ro=true,lock=false",
            "--virtio-mmio-block=/data.img,lock=true,ro=false,lock=false");
        assertEquals(List.of("--virtio-mmio-block", "/disk.img,ro=true,lock=false",
            "--virtio-mmio-block=/data.img,lock=false,ro=false"),
            CrosvmExtraDiskOptions.forAndroidSharedStorage(arguments));
    }

    @Test
    public void unrelatedFlagsAndTheContentsOfTheSelectedPathArePreserved() {
        var arguments = List.of("--disk", "/pci.img,lock=true", "--virtio-snd", "backend=aaudio,uid=12123",
            "--virtio-mmio-blocker", "/unrelated.img,lock=true",
            "--virtio-mmio-block=/storage/emulated/0/lock=true folder/disk.img,ro=true");
        assertEquals(List.of("--disk", "/pci.img,lock=true", "--virtio-snd", "backend=aaudio,uid=12123",
            "--virtio-mmio-blocker", "/unrelated.img,lock=true",
            "--virtio-mmio-block=/storage/emulated/0/lock=true folder/disk.img,ro=true,lock=false"),
            CrosvmExtraDiskOptions.forAndroidSharedStorage(arguments));
    }

    @Test
    public void missingDiskArgumentStillReachesCrosvmAsAnArgumentError() {
        for (var arguments : List.of(List.of("--virtio-mmio-block"),
            List.of("--virtio-mmio-block", "--virtio-mmio-gpu"),
            List.of("--virtio-mmio-block=", "--virtio-mmio-block", ""))) {
            assertEquals(arguments, CrosvmExtraDiskOptions.forAndroidSharedStorage(arguments));
        }
    }
}
