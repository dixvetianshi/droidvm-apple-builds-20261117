// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class PackageFileChecksumTest {
    private static final String ABC_SHA256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Test
    public void copiedChunksUseTheirActualByteRanges() throws Exception {
        var checksum = new PackageFileChecksum(ABC_SHA256.toUpperCase(java.util.Locale.ROOT));
        var bytes = "!abc!".getBytes(StandardCharsets.UTF_8);
        checksum.update(bytes, 1, 1);
        checksum.update(bytes, 2, 2);
        assertTrue(checksum.verify());
    }

    @Test
    public void changedPayloadIsRejectedBeforeImportCompletion() {
        var checksum = new PackageFileChecksum(ABC_SHA256);
        var bytes = "abd".getBytes(StandardCharsets.UTF_8);
        checksum.update(bytes, 0, bytes.length);
        assertThrows(IOException.class, checksum::verify);
    }

    @Test
    public void legacyPackagesWithoutADigestStayImportableButUnverified() throws Exception {
        for (var declaration : new String[]{null, ""}) {
            var checksum = new PackageFileChecksum(declaration);
            var bytes = "legacy image".getBytes(StandardCharsets.UTF_8);
            checksum.update(bytes, 0, bytes.length);
            assertFalse(checksum.verify());
        }
    }

    @Test
    public void malformedDigestCannotBecomeAnOmittedLegacyDigest() {
        assertThrows(IllegalArgumentException.class, () -> new PackageFileChecksum("not-a-sha256"));
    }
}
