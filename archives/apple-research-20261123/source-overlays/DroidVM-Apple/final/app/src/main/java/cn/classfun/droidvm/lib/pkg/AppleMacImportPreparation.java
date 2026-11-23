// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.zip.CRC32;

/** Prepares only this import's verified macOS copies; it never opens an existing VM. */
public final class AppleMacImportPreparation {
    private AppleMacImportPreparation() {}

    private static final int PAGE = 4096;
    private static final int MIB = 1024 * 1024;
    private static final int SECTOR = 512;
    private static final int GPT_ENTRY_BYTES = 128 * 128;
    private static final UUID APFS_PARTITION_TYPE =
        UUID.fromString("69646961-6700-11aa-aa11-00306543ecac");

    public interface Progress {
        void update(String operation, long bytesDone, long bytesTotal, long extraFreeBytes)
            throws IOException;
    }

    /** The complete page window is parsed once, before a new destination is created. */
    private static final class Store {
        final long pages;
        final long logicalBytes;
        final long window;
        final byte[] bitmap;
        final byte[] superblock;
        final long presentBytes;
        final UUID apfsUuid;

        Store(long pages, long window, byte[] bitmap, byte[] superblock, long presentBytes) {
            this.pages = pages;
            this.logicalBytes = pages * PAGE;
            this.window = window;
            this.bitmap = bitmap;
            this.superblock = superblock;
            this.presentBytes = presentBytes;
            var uuid = ByteBuffer.wrap(superblock, 72, 16);
            this.apfsUuid = new UUID(uuid.getLong(), uuid.getLong());
        }

        boolean present(long page) {
            return (bitmap[(int) (page / 8)] & (1 << (page % 8))) != 0;
        }
    }

    /** Readback coverage of a newly created GPT wrapper, not a whole-file digest claim. */
    public static final class PreparedStore {
        public final long logicalBytes;
        public final long sourceWindowBytes;
        public final long diskBytes;
        public final long verifiedPageBytes;
        public final UUID apfsUuid;
        public final UUID diskGuid;
        public final UUID partitionGuid;

        private PreparedStore(Store source, Gpt gpt) {
            logicalBytes = source.logicalBytes;
            sourceWindowBytes = source.window;
            diskBytes = logicalBytes + 2L * MIB;
            verifiedPageBytes = source.presentBytes;
            apfsUuid = source.apfsUuid;
            diskGuid = gpt.diskGuid;
            partitionGuid = gpt.partitionGuid;
        }
    }

    /**
     * Called after the package stream and every member have been verified, before remapping.
     * The native importer supplies its identified profile once. Other guests use the ordinary
     * importer. An incomplete Mac source fails and is cleaned up by its VMImportTask owner.
     */
    @Nullable
    public static AppleMacPreparationResult prepare(
        @Nullable AppleGuestImportProfile.Guest guest, @NonNull List<DiskEntry> disks,
        @NonNull List<BootFile> boots, @NonNull File newImportDirectory,
        @Nullable File psciKernel, @Nullable Progress progress
    ) throws IOException {
        if (guest != AppleGuestImportProfile.Guest.MACOS)
            return null;
        AppleGuestImportProfile.requireVerifiedMacSources(disks, boots);
        var boot = disk(disks, "disks/boot.img");
        var store = disk(disks, "disks/data-store.img");
        requireOwnedFile(newImportDirectory, boot.target);
        requireOwnedFile(newImportDirectory, store.target);
        requireOwnedFile(new File(newImportDirectory, "boot"), boots.get(0).target);
        if (boot.target.getCanonicalFile().equals(store.target.getCanonicalFile()))
            throw new IOException("macOS source disks share a file");
        if (boot.target.length() != boot.size || store.target.length() != store.size
            || boots.get(0).target.length() != boots.get(0).size)
            throw new IOException("Verified macOS source member length changed before preparation");

        verifyPsciKernelSource(psciKernel);
        var target = new File(newImportDirectory, "data-pcie.img");
        for (int index = 1; target.exists(); index++)
            target = new File(newImportDirectory, "data-pcie_" + index + ".img");
        var prepared = convertEmptySeedStore(store.target, target,
            AppleMacPreparationResult.LOGICAL_BYTES, AppleMacPreparationResult.EMPTY_SEED_SHA256,
            progress);
        if (prepared.verifiedPageBytes != AppleMacPreparationResult.PRESENT_BYTES
            || prepared.sourceWindowBytes != AppleMacPreparationResult.SOURCE_WINDOW_BYTES
            || prepared.diskBytes != AppleMacPreparationResult.DISK_BYTES
            || !AppleMacPreparationResult.APFS_UUID.equals(prepared.apfsUuid.toString()))
            throw new IOException("Prepared macOS disk differs from the verified source layout");

        // The source member's digest describes the unmodified archive bytes, not these copies.
        boot.sha256Verified = false;
        replacePsciKernel(boot.target, psciKernel, progress);
        patchBoot(boot.target, boot.size, BOOT_PATCH, AppleMacPreparationResult.DIRECT_FAT_SHA256, progress);
        var sourceBootPath = boot.target.getPath();
        var bootTarget = new File(newImportDirectory, "boot-esp.img");
        for (int index = 1; bootTarget.exists(); index++)
            bootTarget = new File(newImportDirectory, "boot-esp_" + index + ".img");
        var preparedBoot = wrapBootEsp(boot.target, bootTarget, boot.size,
            AppleMacPreparationResult.DIRECT_FAT_SHA256, progress);
        var sourceStorePath = store.target.getPath();
        Files.delete(boot.target.toPath());
        boot.target = bootTarget;
        Files.delete(store.target.toPath());
        store.sha256Verified = false;
        store.target = target;
        // size and sha256 remain the source archive's provenance. Derived length/hash live only
        // in the native result and cannot be forged by a package's extra manifest fields.
        return AppleMacPreparationResult.completed(newImportDirectory.getPath(), sourceBootPath,
            psciKernel.getPath(), preparedBoot, sourceStorePath, target.getPath(), prepared.diskGuid, prepared.partitionGuid);
    }

    /**
     * Convert an overlay over a caller-verified empty seed into an exclusive new sparse disk.
     * The pinned import supplies the known empty seed identity, already covered by its source
     * member SHA. Smaller same-format fixtures can exercise this production boundary without
     * creating a 48 GiB test disk. The source is read-only and the output must not exist.
     */
    @NonNull
    public static PreparedStore convertEmptySeedStore(
        @NonNull File source, @NonNull File exclusiveTarget, long expectedLogicalBytes,
        @NonNull String emptySeedSha256, @Nullable Progress progress
    ) throws IOException {
        if (expectedLogicalBytes <= 0 || expectedLogicalBytes % PAGE != 0
            || expectedLogicalBytes > AppleMacPreparationResult.LOGICAL_BYTES
            || !emptySeedSha256.matches("[0-9a-f]{64}"))
            throw new IOException("Empty-seed store profile is outside the supported macOS layout");
        if (!Files.isRegularFile(source.toPath(), LinkOption.NOFOLLOW_LINKS))
            throw new IOException("macOS store source is not a regular file");
        boolean created = false;
        try (var input = FileChannel.open(source.toPath(), StandardOpenOption.READ)) {
            var store = readStore(input, expectedLogicalBytes, emptySeedSha256);
            var extra = store.presentBytes + 2L * MIB;
            update(progress, "Preparing macOS GPT/APFS disk", 0, store.presentBytes, extra);
            var parent = exclusiveTarget.getAbsoluteFile().getParentFile();
            if (parent == null || !parent.isDirectory())
                throw new IOException("Prepared macOS disk has no destination directory");
            if (parent.getUsableSpace() < extra)
                throw new IOException("macOS disk preparation temporarily needs " + extra
                    + " additional free bytes in the import directory");
            var gpt = new Gpt(store.logicalBytes, APFS_PARTITION_TYPE, "DroidVM Container");
            try (var output = FileChannel.open(exclusiveTarget.toPath(), StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.SPARSE)) {
                created = true;
                // Only a brand-new file can safely supply zero bytes for absent overlay pages.
                // SPARSE is a filesystem hint; the space check conservatively covers every
                // present page plus the two GPT regions, including present all-zero pages.
                write(output, new byte[1], 1, store.logicalBytes + 2L * MIB - 1);
                write(output, gpt.prefix, MIB, 0);
                write(output, gpt.suffix, MIB, MIB + store.logicalBytes);
                var bytes = new byte[MIB];
                var check = new byte[MIB];
                long verified = 0;
                for (long page = 0; page < store.pages;) {
                    requireRunning();
                    if (!store.present(page)) { page++; continue; }
                    long start = page++;
                    while (page < store.pages && page - start < 256 && store.present(page)) page++;
                    int count = (int) ((page - start) * PAGE);
                    read(input, bytes, count, store.window + start * PAGE);
                    long at = MIB + start * PAGE;
                    write(output, bytes, count, at);
                    read(output, check, count, at);
                    if (!Arrays.equals(bytes, 0, count, check, 0, count))
                        throw new IOException("Prepared macOS disk readback mismatch at page " + start);
                    verified += count;
                    update(progress, "Preparing macOS GPT/APFS disk", verified, store.presentBytes, extra);
                }
                output.force(true);
                read(output, check, MIB, 0);
                if (!Arrays.equals(check, gpt.prefix))
                    throw new IOException("Prepared macOS primary GPT region differs from its bytes");
                verifyGptHeader(check, SECTOR, 2 * SECTOR);
                read(output, check, MIB, MIB + store.logicalBytes);
                if (!Arrays.equals(check, gpt.suffix))
                    throw new IOException("Prepared macOS backup GPT region differs from its bytes");
                verifyGptHeader(check, MIB - SECTOR, MIB - SECTOR - GPT_ENTRY_BYTES);
                read(output, check, PAGE, MIB);
                if (!Arrays.equals(store.superblock, 0, PAGE, check, 0, PAGE)
                    || verified != store.presentBytes || output.size() != store.logicalBytes + 2L * MIB)
                    throw new IOException("Prepared macOS disk coverage or APFS superblock is incomplete");
                requireRunning();
                return new PreparedStore(store, gpt);
            }
        } catch (IOException | RuntimeException failure) {
            if (created) {
                try { Files.delete(exclusiveTarget.toPath()); }
                catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static Store readStore(FileChannel source, long expectedLogicalBytes, String seedSha)
        throws IOException {
        var header = new byte[PAGE];
        read(source, header, PAGE, 0);
        var label = "DroidVMDataStore".getBytes(StandardCharsets.US_ASCII);
        if (!Arrays.equals(label, 0, label.length, header, 0, label.length)
            || little(header).getInt(16) != 1 || !zero(header, 20, PAGE))
            throw new IOException("macOS store label or version is invalid");
        read(source, header, PAGE, PAGE);
        var fields = little(header);
        long pages = fields.getLong(16);
        if (!Arrays.equals("SHNGDATA".getBytes(StandardCharsets.US_ASCII), 0, 8, header, 0, 8)
            || fields.getInt(8) != 1 || fields.getInt(12) != 64
            || pages != expectedLogicalBytes / PAGE || fields.getInt(56) <= 0
            || Integer.toUnsignedLong(fields.getInt(60)) != crc(header, 0, 60)
            || !seedSha.equals(hex(Arrays.copyOfRange(header, 24, 56))) || !zero(header, 64, PAGE))
            throw new IOException("macOS overlay header, empty seed identity or CRC is invalid");
        long bitmapBytes = ((pages + PAGE * 8L - 1) / (PAGE * 8L)) * PAGE;
        long window = 2L * PAGE + bitmapBytes;
        if (source.size() != window + expectedLogicalBytes)
            throw new IOException("macOS overlay size does not cover its declared page window");
        var bitmap = new byte[(int) bitmapBytes];
        read(source, bitmap, bitmap.length, 2L * PAGE);
        long present = 0;
        for (int index = 0; index < bitmap.length; index++) {
            int value = bitmap[index] & 255;
            long first = index * 8L;
            if (first >= pages && value != 0
                || first < pages && first + 8 > pages && (value >>> (pages - first)) != 0)
                throw new IOException("macOS overlay bitmap names pages outside the declared window");
            present += Integer.bitCount(value);
        }
        if ((bitmap[0] & 1) == 0)
            throw new IOException("macOS empty-seed overlay does not contain its APFS superblock");
        var superblock = new byte[PAGE];
        read(source, superblock, PAGE, window);
        fields = little(superblock);
        if (fields.getInt(32) != 0x4253584e || fields.getInt(36) != PAGE
            || fields.getLong(40) != pages || zero(superblock, 72, 88)
            || fields.getLong(0) != apfsChecksum(superblock))
            throw new IOException("macOS overlay does not contain the expected valid APFS container");
        return new Store(pages, window, bitmap, superblock, present * PAGE);
    }

    /** Verified byte facts from this owner's exclusively created boot wrapper. */
    public static final class PreparedBoot {
        public final String path;
        public final long payloadBytes;
        public final String payloadSha256;
        public final long diskBytes;
        public final String diskSha256;
        public final UUID diskGuid;
        public final UUID partitionGuid;

        PreparedBoot(String path, long payloadBytes, String payloadSha256,
                     String diskSha256, UUID diskGuid, UUID partitionGuid) {
            this.path = path;
            this.payloadBytes = payloadBytes;
            this.payloadSha256 = payloadSha256;
            this.diskBytes = payloadBytes + 2L * MIB;
            this.diskSha256 = diskSha256;
            this.diskGuid = diskGuid;
            this.partitionGuid = partitionGuid;
        }
    }

    public static final long PSCI_KC_BYTES = 89866240L;
    public static final String PSCI_KC_SHA256 =
        "1d38f4aa320d2cefe4a6a839c925ef1869b4368d128fd1bc888acbed1682b516";
    private static final long PSCI_KC_OFFSET = 818176L;
    private static final UUID ESP_PARTITION_TYPE =
        UUID.fromString("c12a7328-f81f-11d2-ba4b-00a0c93ec93b");

    private static void verifyPsciKernelSource(File kernel) throws IOException {
        if (kernel == null || !Files.isRegularFile(kernel.toPath(), LinkOption.NOFOLLOW_LINKS)
            || kernel.length() != PSCI_KC_BYTES)
            throw new IOException("macOS import requires its checked App PSCI kernel resource");
        try (var input = FileChannel.open(kernel.toPath(), StandardOpenOption.READ)) {
            var bytes = new byte[MIB];
            var digest = sha256();
            for (long at = 0; at < PSCI_KC_BYTES;) {
                requireRunning();
                int count = (int) Math.min(bytes.length, PSCI_KC_BYTES - at);
                read(input, bytes, count, at);
                digest.update(bytes, 0, count);
                at += count;
            }
            if (!PSCI_KC_SHA256.equals(hex(digest.digest())))
                throw new IOException("macOS App PSCI kernel resource SHA-256 mismatch");
        }
    }

    private static void replacePsciKernel(File ownedBoot, File kernel, Progress progress)
        throws IOException {
        // The original whole-boot SHA establishes this exact same-size FAT KC allocation.
        // Only prepare(), after source and import-directory checks, calls this mutation.
        try (var input = FileChannel.open(kernel.toPath(), StandardOpenOption.READ);
             var output = FileChannel.open(ownedBoot.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            var bytes = new byte[MIB];
            var digest = sha256();
            if (input.size() != PSCI_KC_BYTES || output.size() != 402653184L)
                throw new IOException("macOS PSCI source or owned boot length changed");
            for (long at = 0; at < PSCI_KC_BYTES;) {
                requireRunning();
                int count = (int) Math.min(bytes.length, PSCI_KC_BYTES - at);
                read(input, bytes, count, at);
                digest.update(bytes, 0, count);
                write(output, bytes, count, PSCI_KC_OFFSET + at);
                at += count;
                update(progress, "Preparing macOS PSCI kernel", at, PSCI_KC_BYTES, 0);
            }
            output.force(true);
            if (!PSCI_KC_SHA256.equals(hex(digest.digest())))
                throw new IOException("macOS PSCI source changed while writing its owned boot copy");
        }
    }

    /** Same GPT producer as Data; a new boot target owns a byte-exact FAT ESP payload. */
    public static PreparedBoot wrapBootEsp(File payload, File exclusiveTarget,
                                          long payloadBytes, String payloadSha256,
                                          Progress progress) throws IOException {
        if (payloadBytes <= 0 || payloadBytes % SECTOR != 0 || payloadBytes > 402653184L
            || !payloadSha256.matches("[0-9a-f]{64}")
            || !Files.isRegularFile(payload.toPath(), LinkOption.NOFOLLOW_LINKS)
            || payload.getCanonicalFile().equals(exclusiveTarget.getCanonicalFile()))
            throw new IOException("macOS boot ESP source identity or geometry is invalid");
        var parent = exclusiveTarget.getAbsoluteFile().getParentFile();
        long diskBytes = payloadBytes + 2L * MIB;
        if (parent == null || !parent.isDirectory() || parent.getUsableSpace() < diskBytes)
            throw new IOException("macOS boot ESP needs " + diskBytes + " additional free bytes");
        boolean created = false;
        try (var input = FileChannel.open(payload.toPath(), StandardOpenOption.READ)) {
            if (input.size() != payloadBytes)
                throw new IOException("macOS boot ESP payload length changed");
            var gpt = new Gpt(payloadBytes, ESP_PARTITION_TYPE, "DroidVM Boot ESP");
            update(progress, "Preparing macOS GPT/ESP boot", 0, payloadBytes, diskBytes);
            try (var output = FileChannel.open(exclusiveTarget.toPath(), StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                created = true;
                write(output, gpt.prefix, MIB, 0);
                write(output, gpt.suffix, MIB, MIB + payloadBytes);
                var bytes = new byte[MIB];
                var check = new byte[MIB];
                var payloadDigest = sha256();
                for (long at = 0; at < payloadBytes;) {
                    requireRunning();
                    int count = (int) Math.min(bytes.length, payloadBytes - at);
                    read(input, bytes, count, at);
                    write(output, bytes, count, MIB + at);
                    read(output, check, count, MIB + at);
                    if (!Arrays.equals(bytes, 0, count, check, 0, count))
                        throw new IOException("macOS boot ESP payload readback mismatch");
                    payloadDigest.update(check, 0, count);
                    at += count;
                    update(progress, "Preparing macOS GPT/ESP boot", at, payloadBytes, diskBytes);
                }
                output.force(true);
                if (!payloadSha256.equals(hex(payloadDigest.digest())) || output.size() != diskBytes)
                    throw new IOException("macOS boot ESP payload digest or length differs");
                read(output, check, MIB, 0);
                if (!Arrays.equals(check, gpt.prefix))
                    throw new IOException("macOS boot primary GPT metadata readback differs");
                verifyGptHeader(check, SECTOR, 2 * SECTOR);
                read(output, check, MIB, MIB + payloadBytes);
                if (!Arrays.equals(check, gpt.suffix))
                    throw new IOException("macOS boot backup GPT metadata readback differs");
                verifyGptHeader(check, MIB - SECTOR, MIB - SECTOR - GPT_ENTRY_BYTES);
                var diskDigest = sha256();
                for (long at = 0; at < diskBytes;) {
                    requireRunning();
                    int count = (int) Math.min(bytes.length, diskBytes - at);
                    read(output, bytes, count, at);
                    diskDigest.update(bytes, 0, count);
                    at += count;
                }
                update(progress, "Verifying macOS GPT/ESP boot", diskBytes, diskBytes, 0);
                requireRunning();
                return new PreparedBoot(exclusiveTarget.getPath(), payloadBytes, payloadSha256,
                    hex(diskDigest.digest()), gpt.diskGuid, gpt.partitionGuid);
            }
        } catch (IOException | RuntimeException failure) {
            if (created) {
                try { Files.delete(exclusiveTarget.toPath()); }
                catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static final class Gpt {
        final UUID diskGuid = UUID.randomUUID();
        final UUID partitionGuid = UUID.randomUUID();
        final byte[] prefix = new byte[MIB];
        final byte[] suffix = new byte[MIB];

        Gpt(long logicalBytes, UUID partitionType, String partitionLabel) {
            long sectors = (logicalBytes + 2L * MIB) / SECTOR;
            var entries = new byte[GPT_ENTRY_BYTES];
            putGuid(entries, 0, partitionType);
            putGuid(entries, 16, partitionGuid);
            little(entries).putLong(32, MIB / SECTOR)
                .putLong(40, MIB / SECTOR + logicalBytes / SECTOR - 1);
            var name = partitionLabel.getBytes(StandardCharsets.UTF_16LE);
            System.arraycopy(name, 0, entries, 56, name.length);
            // Protective MBR, followed by standard 128-entry primary and backup GPT tables.
            prefix[447] = 0; prefix[448] = 2; prefix[449] = 0;
            prefix[450] = (byte) 0xee;
            prefix[451] = (byte) 255; prefix[452] = (byte) 255; prefix[453] = (byte) 255;
            little(prefix).putInt(454, 1).putInt(458, (int) Math.min(sectors - 1, 0xffffffffL));
            prefix[510] = 0x55; prefix[511] = (byte) 0xaa;
            System.arraycopy(header(1, sectors - 1, 2, sectors, entries), 0, prefix, SECTOR, SECTOR);
            System.arraycopy(entries, 0, prefix, 2 * SECTOR, entries.length);
            System.arraycopy(entries, 0, suffix, MIB - SECTOR - entries.length, entries.length);
            System.arraycopy(header(sectors - 1, 1, sectors - 33, sectors, entries), 0,
                suffix, MIB - SECTOR, SECTOR);
        }

        private byte[] header(long at, long other, long table, long sectors, byte[] entries) {
            var bytes = new byte[SECTOR];
            var fields = little(bytes);
            System.arraycopy("EFI PART".getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, 8);
            fields.putInt(8, 0x10000).putInt(12, 92).putLong(24, at).putLong(32, other)
                .putLong(40, 34).putLong(48, sectors - 34).putLong(72, table)
                .putInt(80, 128).putInt(84, 128).putInt(88, (int) crc(entries, 0, entries.length));
            putGuid(bytes, 56, diskGuid);
            fields.putInt(16, (int) crc(bytes, 0, 92));
            return bytes;
        }
    }

    private static void verifyGptHeader(byte[] region, int headerOffset, int tableOffset)
        throws IOException {
        var header = Arrays.copyOfRange(region, headerOffset, headerOffset + 92);
        var fields = little(header);
        long expected = Integer.toUnsignedLong(fields.getInt(16));
        fields.putInt(16, 0);
        if (crc(header, 0, header.length) != expected
            || crc(region, tableOffset, GPT_ENTRY_BYTES) != Integer.toUnsignedLong(fields.getInt(88)))
            throw new IOException("Prepared macOS GPT header or table CRC is invalid");
    }

    private static void putGuid(byte[] bytes, int offset, UUID uuid) {
        long high = uuid.getMostSignificantBits();
        var fields = little(bytes);
        fields.putInt(offset, (int) (high >>> 32)).putShort(offset + 4, (short) (high >>> 16))
            .putShort(offset + 6, (short) high);
        long low = uuid.getLeastSignificantBits();
        for (int index = 0; index < 8; index++)
            bytes[offset + 8 + index] = (byte) (low >>> (56 - 8 * index));
    }

    // Compact same-length offset resource: comparison of the complete source and verified
    // 4 GiB PCI boot disks changed only these 12 bytes, within the original FAT ADT allocation.
    // The eight ADT properties and full digests are retained in boot-adaptation-report.json.
    static final class Patch {
        final long offset;
        final byte[] before;
        final byte[] after;
        Patch(long offset, int... pairs) {
            this.offset = offset;
            before = new byte[pairs.length / 2];
            after = new byte[pairs.length / 2];
            for (int index = 0; index < before.length; index++) {
                before[index] = (byte) pairs[2 * index];
                after[index] = (byte) pairs[2 * index + 1];
            }
        }
    }

    private static final List<Patch> BOOT_PATCH = List.of(
        new Patch(90685559, 0xba, 0x7a),
        new Patch(90685647, 0x3a, 0xfa, 0x01, 0x00),
        new Patch(90697415, 0xba, 0x7a),
        new Patch(90697601, 0x3e, 0xfe, 0x01, 0x00),
        new Patch(90700383, 0xc0, 0x80), new Patch(90700391, 0xc0, 0x80),
        new Patch(90700399, 0x5f, 0x9f), new Patch(90700999, 0xbb, 0x7b),
        new Patch(90701539, 0xbf, 0x7f), new Patch(90701839, 0xbf, 0x7f)
    );

    static void patchBoot(File boot, long expectedBytes, List<Patch> patches,
                          String derivedSha256, Progress progress) throws IOException {
        try (var file = FileChannel.open(boot.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            if (file.size() != expectedBytes)
                throw new IOException("macOS boot length differs from its verified source member");
            long end = 0;
            for (var patch : patches) {
                if (patch.before.length == 0 || patch.before.length != patch.after.length
                    || patch.offset < end || patch.offset > expectedBytes - patch.before.length)
                    throw new IOException("macOS boot offset resource is outside its source allocation");
                var before = new byte[patch.before.length];
                read(file, before, before.length, patch.offset);
                if (!Arrays.equals(before, patch.before))
                    throw new IOException("macOS boot source differs at an approved ADT patch offset");
                end = patch.offset + patch.before.length;
            }
            requireRunning();
            for (var patch : patches) write(file, patch.after, patch.after.length, patch.offset);
            file.force(true);
            var digest = sha256();
            var bytes = new byte[MIB];
            for (long offset = 0; offset < expectedBytes;) {
                requireRunning();
                int count = (int) Math.min(bytes.length, expectedBytes - offset);
                read(file, bytes, count, offset);
                digest.update(bytes, 0, count);
                offset += count;
                update(progress, "Verifying macOS 4 GiB boot disk", offset, expectedBytes, 0);
            }
            if (!derivedSha256.equals(hex(digest.digest())))
                throw new IOException("Prepared macOS boot SHA-256 mismatch");
        }
    }

    private static DiskEntry disk(List<DiskEntry> disks, String archive) throws IOException {
        for (var disk : disks) if (archive.equals(disk.archivePath)) return disk;
        throw new IOException("Verified macOS import is missing " + archive);
    }

    private static void requireOwnedFile(File directory, File file) throws IOException {
        if (file == null || !directory.isDirectory()
            || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
            || !directory.getCanonicalFile().equals(file.getCanonicalFile().getParentFile()))
            throw new IOException("macOS preparation requires a new import-owned regular file");
    }

    private static long apfsChecksum(byte[] block) {
        long low = 0, high = 0;
        var fields = little(block);
        for (int offset = 8; offset < block.length; offset += 4) {
            low = (low + Integer.toUnsignedLong(fields.getInt(offset))) % 0xffffffffL;
            high = (high + low) % 0xffffffffL;
        }
        long checkLow = 0xffffffffL - ((low + high) % 0xffffffffL);
        long checkHigh = 0xffffffffL - ((low + checkLow) % 0xffffffffL);
        return checkHigh << 32 | checkLow;
    }

    private static ByteBuffer little(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static boolean zero(byte[] bytes, int start, int end) {
        for (int index = start; index < end; index++) if (bytes[index] != 0) return false;
        return true;
    }

    private static long crc(byte[] bytes, int offset, int count) {
        var crc = new CRC32();
        crc.update(bytes, offset, count);
        return crc.getValue();
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String hex(byte[] bytes) {
        var text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(Character.forDigit((value >>> 4) & 15, 16));
            text.append(Character.forDigit(value & 15, 16));
        }
        return text.toString();
    }

    private static void read(FileChannel source, byte[] bytes, int count, long offset) throws IOException {
        var buffer = ByteBuffer.wrap(bytes, 0, count);
        while (buffer.hasRemaining()) {
            int read = source.read(buffer, offset);
            if (read <= 0) throw new IOException("macOS preparation file ended before its declared bytes");
            offset += read;
        }
    }

    private static void write(FileChannel target, byte[] bytes, int count, long offset) throws IOException {
        requireRunning();
        var buffer = ByteBuffer.wrap(bytes, 0, count);
        while (buffer.hasRemaining()) {
            int written = target.write(buffer, offset);
            if (written <= 0) throw new IOException("macOS preparation write did not make progress");
            offset += written;
        }
    }

    private static void update(Progress progress, String operation, long done, long total, long extra)
        throws IOException {
        if (progress != null) progress.update(operation, done, total, extra);
    }

    private static void requireRunning() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted())
            throw new InterruptedIOException("macOS import preparation was interrupted");
    }
}
