// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.archive;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipException;

public final class SparseFileOutputStreamTest {
    @Rule public final TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void anAllZeroFileReplacesOldBytesAndKeepsItsLogicalLength() throws Exception {
        var target = temp.newFile("zero.raw");
        Files.write(target.toPath(), new byte[]{1, 2, 3});
        var zeros = new byte[64 * 1024 + 17];
        try (var out = new SparseFileOutputStream(target)) {
            out.write(zeros);
            // A seek past EOF must not write the zero payload.
            assertEquals(0, target.length());
        }
        assertEquals(zeros.length, target.length());
        assertArrayEquals(zeros, Files.readAllBytes(target.toPath()));
    }

    @Test
    public void middleHolesAndZeroTailsPreserveNonzeroDataAndOffsets() throws Exception {
        var target = temp.newFile("mixed.raw");
        var expected = new byte[3 * 4096 + 23];
        expected[0] = 1;
        expected[3 * 4096 - 1] = (byte) 0x80;
        try (var out = new SparseFileOutputStream(target)) {
            out.write(expected, 0, 4096);
            out.write(expected, 4096, 4096);
            assertEquals(4096, target.length());
            out.write(expected, 8192, 4096);
            out.write(expected, 3 * 4096, 23);
        }
        assertArrayEquals(expected, Files.readAllBytes(target.toPath()));
    }

    @Test
    public void byteRangesAndSingleByteWritesNeverDiscardNonzeroValues() throws Exception {
        var target = temp.newFile("ranges.raw");
        var range = new byte[]{9, 0, 0, 9};
        try (var out = new SparseFileOutputStream(target)) {
            out.write(range, 1, 2);
            assertEquals(0, target.length());
            out.write(new byte[]{0, 0, 1});
            out.write(0x100); // OutputStream writes the low eight bits.
            out.write(0x1ff);
            out.write(0);
        }
        assertArrayEquals(new byte[]{0, 0, 0, 0, 1, 0, (byte) 0xff, 0},
            Files.readAllBytes(target.toPath()));
    }

    @Test
    public void anUpstreamInterruptionClosesThePartialFileForItsOwner() throws Exception {
        var target = temp.newFile("partial.raw");
        var out = new SparseFileOutputStream(target);
        assertThrows(InterruptedIOException.class, () -> {
            try (out; var in = new FilterInputStream(new ByteArrayInputStream(new byte[4096])) {
                @Override
                public int read(byte[] bytes, int offset, int length) throws IOException {
                    int count = super.read(bytes, offset, length);
                    if (count < 0) throw new InterruptedIOException("upstream import interrupted");
                    return count;
                }
            }) {
                in.transferTo(out);
            }
        });
        assertEquals(4096, target.length());
        assertArrayEquals(new byte[4096], Files.readAllBytes(target.toPath()));
        out.close();
        assertThrows(IOException.class, () -> out.write(1));
        assertTrue(target.delete());
    }

    @Test
    public void compressedTarEntriesKeepTheirOrderDigestsAndTrailerValidation() throws Exception {
        var disk = new byte[64 * 1024 + 19];
        disk[0] = 42;
        var boot = new byte[]{0, 7, 0, (byte) 0xff, 0};
        var packed = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(packed); var tar = new TarWriter(gzip)) {
            tar.entry("disk.raw", disk);
            tar.entry("firmware.fd", boot);
        }
        var destination = temp.newFolder("valid");
        assertEquals(List.of("disk.raw", "firmware.fd"), extract(packed.toByteArray(), destination));
        var copied = Files.readAllBytes(new File(destination, "disk.raw").toPath());
        assertArrayEquals(disk, copied);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(disk),
            MessageDigest.getInstance("SHA-256").digest(copied));
        assertArrayEquals(boot, Files.readAllBytes(new File(destination, "firmware.fd").toPath()));

        var corrupt = packed.toByteArray();
        corrupt[corrupt.length - 8] ^= 1; // GZIP trailer CRC32.
        var failedDestination = temp.newFolder("bad-crc");
        assertThrows(ZipException.class, () -> extract(corrupt, failedDestination));
    }

    private static List<String> extract(byte[] packed, File destination) throws Exception {
        var entries = new ArrayList<String>();
        try (var gzip = new GZIPInputStream(new ByteArrayInputStream(packed));
             var tar = new TarReader(gzip)) {
            tar.forEach((name, mode, size, content) -> {
                entries.add(name);
                try (var out = new SparseFileOutputStream(new File(destination, name))) {
                    content.transferTo(out);
                }
            });
            // VMImportTask also drains after TAR EOF to validate the compression trailer.
            gzip.transferTo(OutputStream.nullOutputStream());
        }
        return entries;
    }
}
