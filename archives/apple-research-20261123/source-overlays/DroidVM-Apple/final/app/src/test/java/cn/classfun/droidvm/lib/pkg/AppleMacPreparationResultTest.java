// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

import java.io.IOException;
import java.util.UUID;

public final class AppleMacPreparationResultTest {
    private static final String DIRECTORY = "/storage/emulated/0/User folder/macOS (2)";
    private static final UUID DISK_GUID = UUID.fromString("55f68f3e-2608-4982-86a8-aed69f367a03");
    private static final UUID PARTITION_GUID = UUID.fromString("750a8189-ab88-4082-87c7-a45a0e194ffe");

    private static final UUID BOOT_DISK_GUID = UUID.fromString("61792e82-ff2d-4200-beca-d47f741a8639");
    private static final UUID BOOT_PARTITION_GUID = UUID.fromString("180ed3ae-a351-4b49-a5a4-d6e8a567b450");

    /** Typed completion facts for the native importer boundary; no disk file is allocated. */
    public static AppleMacPreparationResult nativeFacts(String directory) throws IOException {
        var boot = new AppleMacImportPreparation.PreparedBoot(directory + "/boot.img", 402653184L,
            AppleMacPreparationResult.DIRECT_FAT_SHA256, "a".repeat(64), BOOT_DISK_GUID, BOOT_PARTITION_GUID);
        return AppleMacPreparationResult.completed(directory, directory + "/source-boot.img",
            "/data/data/cn.classfun.droidvm.apple/usr/share/droidvm/apple/macos-27.2-psci-kc.bin", boot,
            directory + "/data-store.img", directory + "/data-pcie.img", DISK_GUID, PARTITION_GUID);
    }

    @Test
    public void completedFactsBindImmutablyAndCannotBeReassignedToAnotherVm() throws Exception {
        var id = UUID.randomUUID();
        var otherId = UUID.randomUUID();
        var completed = nativeFacts(DIRECTORY);
        assertThrows(IOException.class, () -> completed.toJson(id));
        var bound = completed.bindToVM(id);
        assertNotSame(completed, bound);
        assertEquals(completed.directory, bound.directory);
        assertEquals(completed.bootPath, bound.bootPath);
        assertEquals(completed.sourceStorePath, bound.sourceStorePath);
        assertEquals(completed.diskPath, bound.diskPath);
        assertEquals(completed.diskGuid, bound.diskGuid);
        assertEquals(completed.partitionGuid, bound.partitionGuid);
        assertSame(bound, bound.bindToVM(id));
        assertThrows(IOException.class, () -> bound.bindToVM(otherId));
        assertThrows(IOException.class, () -> bound.toJson(otherId));
        assertThrows(IOException.class, () -> completed.toJson(id));
        assertEquals(id.toString(), bound.toJson(id).getString("vm_id"));
    }

    @Test
    public void completionRequiresOneAbsoluteDirectoryAndDistinctSourceAndOutputPaths() {
        for (String directory : new String[]{null, "storage/emulated/0/macOS",
            "/storage/emulated/0/macOS/", "/storage/emulated/0/mac\0OS"}) {
            assertThrows(IOException.class, () -> nativeFacts(directory));
        }
        var boot = DIRECTORY + "/boot.img";
        var source = DIRECTORY + "/data-store.img";
        var disk = DIRECTORY + "/data-pcie.img";
        for (String[] paths : new String[][]{
            {"/storage/emulated/0/another VM/boot.img", source, disk},
            {boot, "/storage/emulated/0/another VM/data-store.img", disk},
            {boot, source, "/storage/emulated/0/another VM/data-pcie.img"},
            {"relative/boot.img", source, disk},
            {boot, source + "/", disk},
            {boot, source, DIRECTORY + "/data-pcie\0.img"},
            {null, source, disk}, {boot, null, disk}, {boot, source, null},
            {source, source, disk}, {disk, source, disk}, {boot, source, source}
        }) {
            assertThrows(IOException.class, () -> AppleMacPreparationResult.completed(
                DIRECTORY, DIRECTORY + "/source-boot.img", "/data/data/cn.classfun.droidvm.apple/kc.bin",
                new AppleMacImportPreparation.PreparedBoot(paths[0], 402653184L,
                    AppleMacPreparationResult.DIRECT_FAT_SHA256, "a".repeat(64), DISK_GUID, PARTITION_GUID),
                paths[1], paths[2], DISK_GUID, PARTITION_GUID));
        }
    }

    @Test
    public void nativeFactsMatchOnlyTheirBoundVmAndActualModifiedCopyPlacements() throws Exception {
        var id = UUID.randomUUID();
        var completed = nativeFacts(DIRECTORY);
        var bound = completed.bindToVM(id);
        var manifest = AppleGuestImportProfileTest.verifiedManifest(AppleGuestImportProfile.Guest.MACOS);
        AppleGuestImportProfileTest.completeImport(manifest, DIRECTORY);
        var boot = manifest.disks.get(0);
        var disk = manifest.disks.get(1);
        boot.sha256Verified = false;
        disk.sha256Verified = false;
        boot.ref.path = bound.bootPath;
        disk.ref.path = bound.diskPath;
        bound.requireMatches(id, DIRECTORY, boot, disk);
        assertThrows(IOException.class, () -> completed.requireMatches(id, DIRECTORY, boot, disk));
        assertThrows(IOException.class, () -> bound.requireMatches(UUID.randomUUID(), DIRECTORY, boot, disk));
        assertThrows(IOException.class, () -> bound.requireMatches(id, DIRECTORY + " copy", boot, disk));
        boot.ref.path = "/storage/emulated/0/another VM/boot.img";
        assertThrows(IOException.class, () -> bound.requireMatches(id, DIRECTORY, boot, disk));
        boot.ref.path = bound.bootPath;
        disk.ref.path = bound.sourceStorePath;
        assertThrows(IOException.class, () -> bound.requireMatches(id, DIRECTORY, boot, disk));
        boot.ref.path = bound.bootPath;
        disk.ref.path = bound.diskPath;
        boot.sha256Verified = true;
        assertThrows(IOException.class, () -> bound.requireMatches(id, DIRECTORY, boot, disk));
        boot.sha256Verified = false;
        disk.sha256Verified = true;
        assertThrows(IOException.class, () -> bound.requireMatches(id, DIRECTORY, boot, disk));
        disk.sha256Verified = false;
        bound.requireMatches(id, DIRECTORY, boot, disk);
    }

    @Test
    public void serializedNativeFactsPreserveOriginalMembersAndDerivedReadbackProvenance() throws Exception {
        var id = UUID.randomUUID();
        var bound = nativeFacts(DIRECTORY).bindToVM(id);
        var json = bound.toJson(id);
        var source = AppleGuestImportProfileTest.verifiedManifest(AppleGuestImportProfile.Guest.MACOS);
        var boot = source.disks.get(0);
        var store = source.disks.get(1);
        assertEquals(AppleMacPreparationResult.PROFILE, json.getString("profile"));
        assertEquals(id.toString(), json.getString("vm_id"));
        assertEquals(DIRECTORY, json.getString("import_directory"));
        assertEquals(boot.archivePath, json.getString("source_boot_archive"));
        assertEquals(boot.size, json.getLong("source_boot_bytes"));
        assertEquals(boot.sha256, json.getString("source_boot_sha256"));
        assertEquals(bound.sourceBootPath, json.getString("source_boot_path"));
        assertEquals(store.archivePath, json.getString("source_store_archive"));
        assertEquals(store.size, json.getLong("source_store_bytes"));
        assertEquals(store.sha256, json.getString("source_store_sha256"));
        assertEquals(bound.sourceStorePath, json.getString("source_store_path"));
        assertEquals(AppleMacPreparationResult.SOURCE_WINDOW_BYTES, json.getLong("source_store_window_bytes"));
        assertEquals(AppleMacPreparationResult.EMPTY_SEED_SHA256, json.getString("empty_seed_sha256"));
        assertEquals(bound.bootPath, json.getString("derived_boot_path"));
        assertEquals(bound.preparedBoot.diskBytes, json.getLong("derived_boot_bytes"));
        assertEquals(bound.preparedBoot.diskSha256, json.getString("derived_boot_sha256"));
        assertEquals(boot.size + 2L * AppleMacPreparationResult.PARTITION_OFFSET_BYTES, json.getLong("derived_boot_bytes"));
        assertNotEquals(boot.size, json.getLong("derived_boot_bytes"));
        assertEquals(AppleMacImportPreparation.PSCI_KC_BYTES, json.getLong("source_kernel_bytes"));
        assertEquals(AppleMacImportPreparation.PSCI_KC_SHA256, json.getString("source_kernel_sha256"));
        assertEquals(AppleMacPreparationResult.DIRECT_FAT_SHA256, json.getString("derived_direct_fat_sha256"));
        assertNotEquals(json.getString("derived_direct_fat_sha256"), json.getString("derived_boot_sha256"));
        assertEquals(BOOT_DISK_GUID.toString(), json.getString("derived_boot_disk_guid"));
        assertEquals(BOOT_PARTITION_GUID.toString(), json.getString("derived_boot_partition_guid"));
        assertEquals(AppleMacPreparationResult.PARTITION_OFFSET_BYTES, json.getLong("derived_boot_esp_offset_bytes"));
        assertEquals(boot.size, json.getLong("derived_boot_esp_bytes"));
        assertEquals(Boolean.TRUE, json.get("source_kernel_sha256_verified"));
        assertEquals(Boolean.TRUE, json.get("owned_source_boot_removed"));
        assertEquals(Boolean.TRUE, json.get("owned_direct_fat_removed"));
        assertNotEquals(boot.sha256, json.getString("derived_boot_sha256"));
        assertEquals(bound.diskPath, json.getString("derived_disk_path"));
        assertEquals(AppleMacPreparationResult.DISK_BYTES, json.getLong("derived_disk_bytes"));
        assertNotEquals(store.size, json.getLong("derived_disk_bytes"));
        assertEquals(AppleMacPreparationResult.LOGICAL_BYTES, json.getLong("apfs_logical_bytes"));
        assertEquals(AppleMacPreparationResult.PARTITION_OFFSET_BYTES, json.getLong("apfs_partition_offset_bytes"));
        assertEquals(AppleMacPreparationResult.APFS_UUID, json.getString("apfs_uuid"));
        for (String key : new String[]{"present_page_bytes", "copied_page_bytes", "verified_page_bytes"})
            assertEquals(AppleMacPreparationResult.PRESENT_BYTES, json.getLong(key));
        for (String key : new String[]{"original_members_verified", "derived_boot_sha256_verified",
            "zero_seed_holes_preserved", "gpt_crc_and_bytes_verified", "apfs_superblock_preserved",
            "owned_source_store_removed"})
            assertEquals(Boolean.TRUE, json.get(key));
        assertEquals(DISK_GUID.toString(), json.getString("disk_guid"));
        assertEquals(PARTITION_GUID.toString(), json.getString("partition_guid"));

        json.put("source_store_sha256", "package-supplied claim");
        json.put("derived_disk_path", "/storage/emulated/0/another VM/data-pcie.img");
        var again = bound.toJson(id);
        assertEquals(store.sha256, again.getString("source_store_sha256"));
        assertEquals(bound.diskPath, again.getString("derived_disk_path"));
    }
}
