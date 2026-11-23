// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm.pkg;

import static cn.classfun.droidvm.lib.pkg.AppleGuestImportProfileTest.verifiedManifest;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile;
import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile.Guest;
import cn.classfun.droidvm.lib.pkg.PackageManifest;

public final class VMImportTaskIpadFloorTest {
    private static final String OLD_BOOT = "8bedfd8dc7ffde37d35d8c49816d404f7c27deedb85d460534c365324027638f";
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();

    private static byte[] metadataPrefix(PackageManifest manifest, int volumeCount,
                                         JSONObject json) throws Exception {
        var bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        var header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.put("VMPKG\0".getBytes(StandardCharsets.UTF_8));
        header.putShort((short) manifest.manifestVersion);
        header.putShort((short) manifest.appVersionCode);
        header.putShort((short) bytes.length);
        header.putShort((short) manifest.compression.type);
        header.putShort((short) volumeCount);
        header.putLong(1L << 35); // Declared large disks; the fixture has metadata only.
        var prefix = new byte[4096 + bytes.length];
        System.arraycopy(header.array(), 0, prefix, 0, 24);
        System.arraycopy(bytes, 0, prefix, 4096, bytes.length);
        return prefix;
    }

    private static final class MetadataOnlyStream extends InputStream {
        private final byte[] prefix;
        private int offset;
        int payloadReads;

        MetadataOnlyStream(byte[] prefix) { this.prefix = prefix; }
        @Override public int read() {
            if (offset == prefix.length) {
                payloadReads++;
                throw new AssertionError("Compressed disk payload was touched");
            }
            return prefix[offset++] & 255;
        }
        @Override public int read(byte[] bytes, int at, int length) {
            if (length == 0) return 0;
            if (offset == prefix.length) return read();
            int count = Math.min(length, prefix.length - offset);
            System.arraycopy(prefix, offset, bytes, at, count);
            offset += count;
            return count;
        }
    }

    private static PackageManifest oldManifest() {
        var manifest = verifiedManifest(Guest.IPADOS);
        manifest.disks.get(0).sha256 = OLD_BOOT;
        return manifest;
    }

    @Test
    public void singleAndMultiVolumeOldPackagesAreRefusedBeforeAnyPayloadRead() throws Exception {
        for (int volumes : new int[]{0, 2}) {
            var manifest = oldManifest();
            var stream = new MetadataOnlyStream(metadataPrefix(manifest, volumes, manifest.toJson()));
            var error = assertThrows(IOException.class, () -> VMImportTask.requireSupportedSource(stream));
            assertTrue(error.getMessage().contains("修复版 iPadOS .vmpkg"));
            assertEquals(0, stream.payloadReads);
        }
    }

    @Test
    public void fakeGuestPreparationAndExporterNameCannotTurnOldBootIntoGenericImport() throws Exception {
        var manifest = oldManifest();
        manifest.vm.setName("Ordinary imported VM");
        manifest.appVersion = "other exporter";
        var json = manifest.toJson();
        json.put("guest_preparation", new JSONObject().put("status", "complete")
            .put("sha256", "5d62008d8f5b5e5e4a1ad952a1520f37a9aa4f35e00b6853770dba4be243709c")
            .put("bytes_verified", true));
        var stream = new MetadataOnlyStream(metadataPrefix(manifest, 0, json));
        assertThrows(IOException.class, () -> VMImportTask.requireSupportedSource(stream));
        assertEquals(0, stream.payloadReads);
    }

    @Test
    public void realUnpackRefusesOldPackageBeforeCreatingTargetOrVmDirectory() throws Exception {
        var manifest = oldManifest();
        var master = temporary.newFile("old.vmpkg");
        Files.write(master.toPath(), metadataPrefix(manifest, 0, manifest.toJson()));
        var target = new File(temporary.getRoot(), "not-created");
        var task = new VMImportTask(null, new JSONObject()
            .put("src_path", "/metadata-fixture").put("target_dir", "/fixture-target"));
        var sourceField = VMImportTask.class.getDeclaredField("srcPath");
        sourceField.setAccessible(true);
        sourceField.set(task, master.getAbsolutePath());
        var targetField = VMImportTask.class.getDeclaredField("targetDir");
        targetField.setAccessible(true);
        targetField.set(task, target);
        var unpack = VMImportTask.class.getDeclaredMethod("unpack");
        unpack.setAccessible(true);
        var error = assertThrows(InvocationTargetException.class, () -> unpack.invoke(task));
        assertTrue(error.getCause() instanceof IOException);
        assertTrue(error.getCause().getMessage().contains("修复版 iPadOS .vmpkg"));
        assertFalse(target.exists());
        var vmDir = VMImportTask.class.getDeclaredField("vmDir");
        vmDir.setAccessible(true);
        assertNull(vmDir.get(task));
        assertNull(task.importedVM);
        assertTrue(task.placedDisks.isEmpty());
        assertTrue(task.placedBoots.isEmpty());
    }

    @Test
    public void floorMacAndUnknownPackagePreflightNeverReadsCompressedPayload() throws Exception {
        for (int kind = 0; kind < 3; kind++) {
            var manifest = verifiedManifest(kind == 1 ? Guest.MACOS : Guest.IPADOS);
            if (kind == 2) {
                manifest.appVersion = "ordinary exporter";
                manifest.disks.get(0).sha256 = "a".repeat(64);
            }
            var stream = new MetadataOnlyStream(metadataPrefix(manifest, 0, manifest.toJson()));
            VMImportTask.requireSupportedSource(stream);
            assertEquals(0, stream.payloadReads);
            if (kind == 0) assertEquals(Guest.IPADOS, AppleGuestImportProfile.identify(manifest));
            if (kind == 1) assertEquals(Guest.MACOS, AppleGuestImportProfile.identify(manifest));
            if (kind == 2) assertNull(AppleGuestImportProfile.identify(manifest));
        }
    }
}
