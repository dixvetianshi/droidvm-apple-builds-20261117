// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.zip.CRC32;

public final class AppleMacImportPreparationTest {
    private static final int PAGE = 4096;
    private static final int MIB = 1024 * 1024;
    private static final int PAGES = 300;
    private static final int WINDOW = 3 * PAGE;
    private static final String SEED = emptySeedDigest();
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();

    /** A tiny empty-seed overlay with a valid APFS header and deliberately stale absent page. */
    private File store() throws Exception {
        var source = temporary.newFile();
        var header = new byte[PAGE];
        System.arraycopy("SHNGDATA".getBytes(StandardCharsets.US_ASCII), 0, header, 0, 8);
        little(header).putInt(8, 1).putInt(12, 64).putLong(16, PAGES).putInt(56, 1);
        System.arraycopy(java.util.HexFormat.of().parseHex(SEED), 0, header, 24, 32);
        little(header).putInt(60, (int) crc(header, 0, 60));
        var bitmap = new byte[PAGE];
        for (int page = 0; page < 260; page++) bitmap[page / 8] |= (byte) (1 << (page % 8));
        bitmap[299 / 8] |= (byte) (1 << (299 % 8));
        var superblock = new byte[PAGE];
        little(superblock).putInt(32, 0x4253584e).putInt(36, PAGE).putLong(40, PAGES);
        var uuid = ByteBuffer.wrap(superblock);
        uuid.putLong(72, 0xa2970b5286884980L).putLong(80, 0x817719d960c23ae8L);
        // APFS checksum is the two complementary Fletcher sums over its payload.
        long first = 0, second = 0;
        for (int at = 8; at < PAGE; at += 4) {
            first += Integer.toUnsignedLong(little(superblock).getInt(at));
            second += first;
        }
        first %= 0xffffffffL;
        second %= 0xffffffffL;
        long low = 0xffffffffL - ((first + second) % 0xffffffffL);
        long high = 0xffffffffL - ((first + low) % 0xffffffffL);
        little(superblock).putLong(0, high << 32 | low);
        try (var file = new RandomAccessFile(source, "rw")) {
            file.setLength(WINDOW + PAGES * (long) PAGE);
            file.write("DroidVMDataStore".getBytes(StandardCharsets.US_ASCII));
            file.write(new byte[]{1, 0, 0, 0});
            file.seek(PAGE); file.write(header);
            file.seek(2L * PAGE); file.write(bitmap);
            file.seek(WINDOW); file.write(superblock);
            var page = new byte[PAGE];
            for (int index = 1; index < 260; index++) {
                Arrays.fill(page, (byte) index);
                file.seek(WINDOW + index * (long) PAGE); file.write(page);
            }
            Arrays.fill(page, (byte) 0x65);
            file.seek(WINDOW + 270L * PAGE); file.write(page); // absent, must become zero
            Arrays.fill(page, (byte) 0x73);
            file.seek(WINDOW + 299L * PAGE); file.write(page);
        }
        return source;
    }

    private File target() throws IOException {
        return new File(temporary.getRoot(), UUID.randomUUID() + ".img");
    }

    @Test
    public void publicConverterPreservesAllPresentPagesAndZerosAbsentSourceBytes() throws Exception {
        var source = store();
        var before = Files.readAllBytes(source.toPath());
        var output = target();
        var result = AppleMacImportPreparation.convertEmptySeedStore(source, output,
            PAGES * (long) PAGE, SEED, null);
        assertEquals(261L * PAGE, result.verifiedPageBytes);
        assertEquals(WINDOW, result.sourceWindowBytes);
        assertEquals(PAGES * (long) PAGE + 2L * MIB, output.length());
        assertEquals(UUID.fromString(AppleMacPreparationResult.APFS_UUID), result.apfsUuid);
        try (var original = new RandomAccessFile(source, "r");
             var actual = new RandomAccessFile(output, "r")) {
            var expected = new byte[PAGE];
            var page = new byte[PAGE];
            for (int index = 0; index < PAGES; index++) {
                actual.seek(MIB + index * (long) PAGE); actual.readFully(page);
                if (index < 260 || index == 299) {
                    original.seek(WINDOW + index * (long) PAGE); original.readFully(expected);
                } else Arrays.fill(expected, (byte) 0);
                assertArrayEquals("logical APFS page " + index, expected, page);
            }
            var prefix = new byte[MIB];
            var suffix = new byte[MIB];
            actual.seek(0); actual.readFully(prefix);
            actual.seek(MIB + PAGES * (long) PAGE); actual.readFully(suffix);
            assertEquals(0x55, prefix[510] & 255);
            assertEquals(0xaa, prefix[511] & 255);
            assertEquals(0xee, prefix[450] & 255);
            assertArrayEquals(java.util.HexFormat.of().parseHex("616964690067aa11aa1100306543ecac"),
                Arrays.copyOfRange(prefix, 1024, 1040));
            assertEquals(2048L, little(prefix).getLong(1024 + 32));
            assertEquals(2048L + PAGES * 8L - 1, little(prefix).getLong(1024 + 40));
            assertGptCrc(prefix, 512, 1024);
            assertGptCrc(suffix, MIB - 512, MIB - 512 - 16384);
            assertArrayEquals(Arrays.copyOfRange(prefix, 1024, 1024 + 16384),
                Arrays.copyOfRange(suffix, MIB - 512 - 16384, MIB - 512));
        }
        assertArrayEquals(before, Files.readAllBytes(source.toPath()));
    }

    @Test
    public void exclusiveTargetCannotReplaceAnExistingFile() throws Exception {
        var source = store();
        var output = temporary.newFile();
        Files.write(output.toPath(), new byte[]{8, 9, 10});
        assertThrows(IOException.class, () -> AppleMacImportPreparation.convertEmptySeedStore(
            source, output, PAGES * (long) PAGE, SEED, null));
        assertArrayEquals(new byte[]{8, 9, 10}, Files.readAllBytes(output.toPath()));
    }

    @Test
    public void invalidHeaderSeedBitmapAndTruncatedWindowFailBeforeCreatingOutput() throws Exception {
        for (int corruption = 0; corruption < 5; corruption++) {
            var source = store();
            try (var file = new RandomAccessFile(source, "rw")) {
                switch (corruption) {
                    case 0: file.seek(PAGE + 60); file.writeInt(0); break;
                    case 1:
                        var header = new byte[PAGE];
                        file.seek(PAGE); file.readFully(header);
                        header[24] ^= 1;
                        little(header).putInt(60, (int) crc(header, 0, 60));
                        file.seek(PAGE); file.write(header);
                        break;
                    case 2: file.seek(2L * PAGE + PAGES / 8); file.write(0x80); break;
                    case 3: file.setLength(file.length() - 1); break;
                    case 4: file.seek(2L * PAGE); file.write(0xfe); break;
                    default: throw new AssertionError();
                }
            }
            var output = target();
            assertThrows(IOException.class, () -> AppleMacImportPreparation.convertEmptySeedStore(
                source, output, PAGES * (long) PAGE, SEED, null));
            assertFalse(output.exists());
        }
    }

    @Test
    public void oversizedProfileIsRejectedWithoutReadingOrAllocatingItsBitmap() throws Exception {
        var output = target();
        assertThrows(IOException.class, () -> AppleMacImportPreparation.convertEmptySeedStore(
            store(), output, Long.MAX_VALUE, SEED, null));
        assertFalse(output.exists());
    }

    @Test
    public void failureDuringCopyAndAtItsLastProgressCallbackRemovesOnlyTheNewTarget() throws Exception {
        for (boolean finalization : List.of(false, true)) {
            var source = store();
            var before = Files.readAllBytes(source.toPath());
            var output = target();
            assertThrows(InterruptedIOException.class, () ->
                AppleMacImportPreparation.convertEmptySeedStore(source, output, PAGES * (long) PAGE,
                    SEED, (operation, done, total, extra) -> {
                        assertEquals(261L * PAGE + 2L * MIB, extra);
                        if (done > 0 && (!finalization || done == total))
                            throw new InterruptedIOException("fixture cancellation");
                    }));
            assertFalse(output.exists());
            assertArrayEquals(before, Files.readAllBytes(source.toPath()));
        }
    }

    @Test
    public void bootOffsetsAreValidatedTogetherBeforeAnyByteChanges() throws Exception {
        var file = temporary.newFile();
        var original = new byte[]{1, 2, 3, 4, 5, 6};
        Files.write(file.toPath(), original);
        assertThrows(IOException.class, () -> AppleMacImportPreparation.patchBoot(file, original.length,
            List.of(new AppleMacImportPreparation.Patch(1, 2, 9),
                new AppleMacImportPreparation.Patch(4, 8, 7)), "0".repeat(64), null));
        assertArrayEquals(original, Files.readAllBytes(file.toPath()));
        var expected = new byte[]{1, 9, 3, 4, 7, 6};
        var sha = MessageDigest.getInstance("SHA-256").digest(expected);
        var hex = java.util.HexFormat.of().formatHex(sha);
        AppleMacImportPreparation.patchBoot(file, original.length,
            List.of(new AppleMacImportPreparation.Patch(1, 2, 9),
                new AppleMacImportPreparation.Patch(4, 5, 7)), hex, null);
        assertArrayEquals(expected, Files.readAllBytes(file.toPath()));
    }

    @Test
    public void nativeOwnerSkipsMacPreparationForOtherAndUnrecognizedGuests() throws Exception {
        var owned = temporary.newFolder();
        assertNull(AppleMacImportPreparation.prepare(null, List.of(), List.of(), owned, null, null));
        assertNull(AppleMacImportPreparation.prepare(AppleGuestImportProfile.Guest.IPADOS,
            List.of(), List.of(), owned, null, null));
        assertEquals(0, owned.list().length);
    }

    @Test
    public void anUnverifiedSourceOrAnotherDirectoriesFilesCannotBePrepared() throws Exception {
        var manifest = AppleGuestImportProfileTest.verifiedManifest(AppleGuestImportProfile.Guest.MACOS);
        var guest = AppleGuestImportProfile.identify(manifest);
        assertEquals(AppleGuestImportProfile.Guest.MACOS, guest);
        var owned = temporary.newFolder();
        assertThrows(IOException.class, () -> AppleMacImportPreparation.prepare(guest,
            manifest.disks, manifest.boots, owned, null, null));
        var outside = temporary.newFile();
        Files.write(outside.toPath(), new byte[]{1, 2, 3});
        for (var disk : manifest.disks) { disk.sha256Verified = true; disk.target = outside; }
        manifest.boots.get(0).sha256Verified = true;
        assertThrows(IOException.class, () -> AppleMacImportPreparation.prepare(guest,
            manifest.disks, manifest.boots, owned, null, null));
        assertArrayEquals(new byte[]{1, 2, 3}, Files.readAllBytes(outside.toPath()));
        assertEquals(0, owned.list().length);
    }

    /** Tiny sector-aligned bytes verify the wrapper owner, not guest/FAT boot. */
    @Test
    public void bootEspWrapperPreservesEveryPayloadByteAndReportsActualGptDiskFacts() throws Exception {
        var source = temporary.newFile();
        var payload = new byte[256 * 1024];
        for (int index = 0; index < payload.length; index++) payload[index] = (byte) (index * 31);
        Files.write(source.toPath(), payload);
        var sha = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        var output = target();
        var result = AppleMacImportPreparation.wrapBootEsp(source, output, payload.length, sha, null);
        assertEquals(output.getPath(), result.path);
        assertEquals(payload.length, result.payloadBytes);
        assertEquals(sha, result.payloadSha256);
        assertEquals(payload.length + 2L * MIB, result.diskBytes);
        assertEquals(result.diskBytes, output.length());
        var whole = Files.readAllBytes(output.toPath());
        assertEquals(java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(whole)), result.diskSha256);
        org.junit.Assert.assertNotEquals(sha, result.diskSha256);
        assertArrayEquals(payload, Arrays.copyOfRange(whole, MIB, MIB + payload.length));
        assertArrayEquals(payload, Files.readAllBytes(source.toPath()));
        var prefix = Arrays.copyOfRange(whole, 0, MIB);
        var suffix = Arrays.copyOfRange(whole, MIB + payload.length, whole.length);
        assertArrayEquals(java.util.HexFormat.of().parseHex("28732ac11ff8d211ba4b00a0c93ec93b"),
            Arrays.copyOfRange(prefix, 1024, 1040));
        assertEquals(2048L, little(prefix).getLong(1024 + 32));
        assertEquals(2048L + payload.length / 512L - 1, little(prefix).getLong(1024 + 40));
        assertGptCrc(prefix, 512, 1024);
        assertGptCrc(suffix, MIB - 512, MIB - 512 - 16384);
        assertArrayEquals(Arrays.copyOfRange(prefix, 1024, 1024 + 16384),
            Arrays.copyOfRange(suffix, MIB - 512 - 16384, MIB - 512));
    }

    @Test
    public void bootEspAliasExistingOutputAndWrongPayloadDigestPreserveSources() throws Exception {
        var source = temporary.newFile();
        var payload = new byte[512];
        Arrays.fill(payload, (byte) 0x73);
        Files.write(source.toPath(), payload);
        var sha = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        assertThrows(IOException.class, () -> AppleMacImportPreparation.wrapBootEsp(
            source, source, payload.length, sha, null));
        var existing = temporary.newFile();
        Files.write(existing.toPath(), new byte[]{9, 8, 7});
        assertThrows(IOException.class, () -> AppleMacImportPreparation.wrapBootEsp(
            source, existing, payload.length, sha, null));
        assertArrayEquals(new byte[]{9, 8, 7}, Files.readAllBytes(existing.toPath()));
        var output = target();
        assertThrows(IOException.class, () -> AppleMacImportPreparation.wrapBootEsp(
            source, output, payload.length, "0".repeat(64), null));
        assertFalse(output.exists());
        assertArrayEquals(payload, Files.readAllBytes(source.toPath()));
    }

    @Test
    public void cancellationAtBootEspFinalReadbackCallbackRemovesOnlyNewDisk() throws Exception {
        var source = temporary.newFile();
        var payload = new byte[512];
        Files.write(source.toPath(), payload);
        var sha = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        var foreign = temporary.newFile();
        Files.write(foreign.toPath(), new byte[]{4, 5, 6});
        var output = target();
        assertThrows(InterruptedIOException.class, () -> AppleMacImportPreparation.wrapBootEsp(
            source, output, payload.length, sha, (operation, done, total, extra) -> {
                if (operation.equals("Verifying macOS GPT/ESP boot") && done == total)
                    throw new InterruptedIOException("fixture cancellation after complete disk readback");
            }));
        assertFalse(output.exists());
        assertArrayEquals(payload, Files.readAllBytes(source.toPath()));
        assertArrayEquals(new byte[]{4, 5, 6}, Files.readAllBytes(foreign.toPath()));
    }

    private static void assertGptCrc(byte[] bytes, int offset, int table) {
        assertArrayEquals("EFI PART".getBytes(StandardCharsets.US_ASCII),
            Arrays.copyOfRange(bytes, offset, offset + 8));
        var header = Arrays.copyOfRange(bytes, offset, offset + 92);
        long stored = Integer.toUnsignedLong(little(header).getInt(16));
        little(header).putInt(16, 0);
        assertEquals(stored, crc(header, 0, 92));
        assertEquals(Integer.toUnsignedLong(little(header).getInt(88)), crc(bytes, table, 16384));
    }

    private static ByteBuffer little(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static long crc(byte[] bytes, int offset, int count) {
        var crc = new CRC32();
        crc.update(bytes, offset, count);
        return crc.getValue();
    }

    private static String emptySeedDigest() {
        try {
            return java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(new byte[PAGES * PAGE]));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
