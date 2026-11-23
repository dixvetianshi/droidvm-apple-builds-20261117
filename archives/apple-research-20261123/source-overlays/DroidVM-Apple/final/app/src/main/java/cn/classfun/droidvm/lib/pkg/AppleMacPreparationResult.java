// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.UUID;

/** Facts produced by the native importer, separate from the package's source manifest. */
public final class AppleMacPreparationResult {
    public static final String PROFILE = "macos-4096-pci-psci-esp-v2";
    public static final long LOGICAL_BYTES = 48L << 30;
    public static final long SOURCE_WINDOW_BYTES = 1581056L;
    public static final long PARTITION_OFFSET_BYTES = 1048576L;
    public static final long DISK_BYTES = LOGICAL_BYTES + 2 * PARTITION_OFFSET_BYTES;
    public static final long PRESENT_BYTES = 21826748416L;
    public static final String EMPTY_SEED_SHA256 =
        "eb2115d5055aa7a97a29af8ebbe5859b6fa4595faab30eacf5f2b69d037b92bf";
    public static final String DIRECT_FAT_SHA256 =
        "b9b5a26622e801d374885d46b7e92ddf87597108fe2683790e9587f059b6814a";
    public static final String APFS_UUID = "a2970b52-8688-4980-8177-19d960c23ae8";

    @Nullable private final UUID vmId;
    @NonNull public final String directory;
    @NonNull public final String bootPath;
    @NonNull public final String sourceBootPath;
    @NonNull public final String sourceKernelPath;
    @NonNull public final AppleMacImportPreparation.PreparedBoot preparedBoot;
    @NonNull public final String sourceStorePath;
    @NonNull public final String diskPath;
    @NonNull public final UUID diskGuid;
    @NonNull public final UUID partitionGuid;

    private AppleMacPreparationResult(@Nullable UUID vmId, String directory, String sourceBootPath, String sourceKernelPath,
                                      AppleMacImportPreparation.PreparedBoot preparedBoot, String sourceStorePath, String diskPath,
                                      UUID diskGuid, UUID partitionGuid) throws IOException {
        this.vmId = vmId;
        this.directory = directory;
        this.bootPath = preparedBoot.path;
        this.sourceBootPath = sourceBootPath;
        this.sourceKernelPath = sourceKernelPath;
        this.preparedBoot = preparedBoot;
        this.sourceStorePath = sourceStorePath;
        this.diskPath = diskPath;
        this.diskGuid = diskGuid;
        this.partitionGuid = partitionGuid;
        requireDirectory(directory);
        if (!AppleGuestImportProfile.deviceParent(sourceBootPath).equals(directory)
            || sourceBootPath.equals(bootPath) || sourceBootPath.equals(diskPath)
            || sourceBootPath.equals(sourceStorePath) || sourceKernelPath == null
            || !sourceKernelPath.startsWith("/") || sourceKernelPath.indexOf('\0') >= 0
            || preparedBoot.payloadBytes != AppleGuestImportProfile.macMember("disks/boot.img").bytes
            || !DIRECT_FAT_SHA256.equals(preparedBoot.payloadSha256)
            || !preparedBoot.diskSha256.matches("[0-9a-f]{64}"))
            throw new IOException("Prepared macOS boot source and derived facts differ");
        if (!AppleGuestImportProfile.deviceParent(bootPath).equals(directory)
            || !AppleGuestImportProfile.deviceParent(sourceStorePath).equals(directory)
            || !AppleGuestImportProfile.deviceParent(diskPath).equals(directory)
            || bootPath.equals(sourceStorePath)
            || bootPath.equals(diskPath) || sourceStorePath.equals(diskPath))
            throw new IOException("Prepared macOS files do not belong to one new import directory");
    }

    /** Called only after source verification, disk readback, boot hashing and source cleanup. */
    static AppleMacPreparationResult completed(String directory, String sourceBootPath, String sourceKernelPath,
                                               AppleMacImportPreparation.PreparedBoot preparedBoot, String sourceStorePath, String diskPath,
                                               UUID diskGuid, UUID partitionGuid) throws IOException {
        return new AppleMacPreparationResult(null, directory, sourceBootPath, sourceKernelPath, preparedBoot, sourceStorePath,
            diskPath, diskGuid, partitionGuid);
    }

    /** Attach the completed native facts to their actual new VM, without a JSON round trip. */
    @NonNull
    public AppleMacPreparationResult bindToVM(@NonNull UUID importedVmId) throws IOException {
        if (vmId != null) {
            if (!vmId.equals(importedVmId))
                throw new IOException("Prepared macOS result cannot be reassigned to another VM");
            return this;
        }
        return new AppleMacPreparationResult(importedVmId, directory, sourceBootPath, sourceKernelPath, preparedBoot, sourceStorePath,
            diskPath, diskGuid, partitionGuid);
    }

    /** Serialize facts already bound by the native owner; package fields never supply them. */
    @NonNull
    public JSONObject toJson(@NonNull UUID importedVmId) throws JSONException, IOException {
        if (vmId == null || !vmId.equals(importedVmId))
            throw new IOException("Prepared macOS result is not bound to this imported VM");
        var boot = AppleGuestImportProfile.macMember("disks/boot.img");
        var store = AppleGuestImportProfile.macMember("disks/data-store.img");
        var result = new JSONObject();
        result.put("profile", PROFILE);
        result.put("vm_id", importedVmId.toString());
        result.put("import_directory", directory);
        result.put("original_members_verified", true);
        result.put("source_boot_archive", boot.archive);
        result.put("source_boot_bytes", boot.bytes);
        result.put("source_boot_sha256", boot.sha256);
        result.put("source_boot_path", sourceBootPath);
        result.put("source_kernel_path", sourceKernelPath);
        result.put("source_kernel_bytes", AppleMacImportPreparation.PSCI_KC_BYTES);
        result.put("source_kernel_sha256", AppleMacImportPreparation.PSCI_KC_SHA256);
        result.put("source_kernel_sha256_verified", true);
        result.put("derived_direct_fat_path", sourceBootPath);
        result.put("derived_direct_fat_bytes", preparedBoot.payloadBytes);
        result.put("derived_direct_fat_sha256", preparedBoot.payloadSha256);
        result.put("source_store_archive", store.archive);
        result.put("source_store_bytes", store.bytes);
        result.put("source_store_sha256", store.sha256);
        result.put("source_store_path", sourceStorePath);
        result.put("source_store_window_bytes", SOURCE_WINDOW_BYTES);
        result.put("empty_seed_sha256", EMPTY_SEED_SHA256);
        result.put("derived_boot_path", bootPath);
        result.put("derived_boot_bytes", preparedBoot.diskBytes);
        result.put("derived_boot_sha256", preparedBoot.diskSha256);
        result.put("derived_boot_disk_guid", preparedBoot.diskGuid.toString());
        result.put("derived_boot_partition_guid", preparedBoot.partitionGuid.toString());
        result.put("derived_boot_esp_offset_bytes", PARTITION_OFFSET_BYTES);
        result.put("derived_boot_esp_bytes", preparedBoot.payloadBytes);
        result.put("derived_boot_esp_type", "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
        result.put("derived_boot_sha256_verified", true);
        result.put("derived_disk_path", diskPath);
        result.put("derived_disk_bytes", DISK_BYTES);
        result.put("apfs_logical_bytes", LOGICAL_BYTES);
        result.put("apfs_partition_offset_bytes", PARTITION_OFFSET_BYTES);
        result.put("apfs_uuid", APFS_UUID);
        result.put("present_page_bytes", PRESENT_BYTES);
        result.put("copied_page_bytes", PRESENT_BYTES);
        result.put("verified_page_bytes", PRESENT_BYTES);
        result.put("zero_seed_holes_preserved", true);
        result.put("gpt_crc_and_bytes_verified", true);
        result.put("apfs_superblock_preserved", true);
        result.put("disk_guid", diskGuid.toString());
        result.put("partition_guid", partitionGuid.toString());
        result.put("owned_source_store_removed", true);
        result.put("owned_source_boot_removed", true);
        result.put("owned_direct_fat_removed", true);
        return result;
    }

    /** Compare native facts to the actual VM and its completed disk placements before binding. */
    void requireMatches(UUID importedVmId, String importDirectory, DiskEntry boot, DiskEntry disk)
        throws IOException {
        if (vmId == null || !vmId.equals(importedVmId) || !directory.equals(importDirectory)
            || !bootPath.equals(boot.ref.path) || !diskPath.equals(disk.ref.path)
            || boot.sha256Verified || disk.sha256Verified)
            throw new IOException("Prepared macOS result differs from the native import placement");
    }

    private static void requireDirectory(String directory) throws IOException {
        if (directory == null || !directory.startsWith("/") || directory.endsWith("/")
            || directory.indexOf('\0') >= 0)
            throw new IOException("Prepared macOS result has no absolute import directory");
    }

}
