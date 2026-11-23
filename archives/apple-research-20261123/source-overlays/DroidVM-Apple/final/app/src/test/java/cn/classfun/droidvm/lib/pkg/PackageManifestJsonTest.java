// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;

import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile.Guest;
import cn.classfun.droidvm.lib.store.vm.VMConfig;

/** The JVM task uses org.json itself, rather than Android's returning-defaults stub. */
public final class PackageManifestJsonTest {
    @Test
    public void declaredDigestsSurviveTheActualManifestParserAndSerializer() throws Exception {
        var source = AppleGuestImportProfileTest.verifiedManifest(Guest.IPADOS);
        var parsed = PackageManifest.fromJson(new JSONObject(source.toJson().toString()));
        assertEquals(Guest.IPADOS, AppleGuestImportProfile.identify(parsed));
        assertEquals(source.disks.get(1).sha256, parsed.disks.get(1).sha256);
        assertEquals(source.boots.get(0).sha256, parsed.boots.get(0).sha256);
        assertFalse(parsed.disks.get(1).sha256Verified);
        assertFalse(parsed.boots.get(0).sha256Verified);
    }

    @Test
    public void legacyManifestsStillParseWithoutInventingChecksumVerification() throws Exception {
        var json = AppleGuestImportProfileTest.verifiedManifest(Guest.MACOS).toJson();
        for (int index = 0; index < json.getJSONArray("disks").length(); index++) {
            json.getJSONArray("disks").getJSONObject(index).remove("sha256");
            json.getJSONArray("disks").getJSONObject(index).remove("sha256_verified");
        }
        json.getJSONArray("boots").getJSONObject(0).remove("sha256");
        json.getJSONArray("boots").getJSONObject(0).remove("sha256_verified");
        var parsed = PackageManifest.fromJson(new JSONObject(json.toString()));
        assertEquals("", parsed.disks.get(0).sha256);
        assertEquals("", parsed.boots.get(0).sha256);
        assertFalse(parsed.disks.get(0).sha256Verified);
        assertFalse(parsed.boots.get(0).sha256Verified);
        assertNull(AppleGuestImportProfile.identify(parsed));
    }

    @Test
    public void completedMembersSerializePlacedPathsInsteadOfTheExportersPaths() throws Exception {
        var source = AppleGuestImportProfileTest.verifiedManifest(Guest.MACOS);
        var disk = source.disks.get(0);
        disk.target = new File("actual-import", "renamed-boot.img");
        disk.sha256Verified = true;
        var boot = source.boots.get(0);
        boot.target = new File("actual-import/boot", "renamed-firmware.fd");
        boot.sha256Verified = true;
        var diskResult = DiskEntry.from(new JSONObject(disk.toJson().toString()));
        var bootResult = BootFile.from(new JSONObject(boot.toJson().toString()));
        assertEquals(disk.target.getPath(), diskResult.ref.path);
        assertEquals(disk.target.getName(), diskResult.name);
        assertEquals(boot.target.getPath(), bootResult.path);
        assertEquals(boot.target.getName(), bootResult.name);
        assertEquals(disk.sha256, diskResult.sha256);
        assertEquals(boot.sha256, bootResult.sha256);
        assertTrue(diskResult.sha256Verified);
        assertTrue(bootResult.sha256Verified);
    }

    @Test
    public void realDoneJsonBindsAllIpadDisksWithoutTouchingTheVmIdentity() throws Exception {
        var source = AppleGuestImportProfileTest.verifiedManifest(Guest.IPADOS);
        AppleGuestImportProfileTest.completeImport(source, "/storage/emulated/0/Actual import/iPad (2)");
        var receipt = new JSONObject();
        receipt.put("phase", "done");
        receipt.put("done", 5);
        receipt.put("total", 5);
        var diskJson = new JSONArray();
        for (var disk : source.disks) diskJson.put(disk.toJson());
        var bootJson = new JSONArray();
        for (var boot : source.boots) bootJson.put(boot.toJson());
        receipt.put("disks", diskJson);
        receipt.put("boots", bootJson);
        var parsed = new JSONObject(receipt.toString());
        var disks = new ArrayList<DiskEntry>();
        for (int index = 0; index < parsed.getJSONArray("disks").length(); index++)
            disks.add(DiskEntry.from(parsed.getJSONArray("disks").get(index)));
        var boots = new ArrayList<BootFile>();
        for (int index = 0; index < parsed.getJSONArray("boots").length(); index++)
            boots.add(BootFile.from(parsed.getJSONArray("boots").get(index)));
        var vm = new VMConfig(new JSONObject(source.vm.toJson().toString()));
        AppleGuestImportProfile.bind(Guest.IPADOS, vm, disks, boots,
            parsed.getInt("done"), parsed.getInt("total"), 12125);
        var options = vm.item.get("extra_options").asArray();
        assertEquals(3, options.stream().filter(value -> "--virtio-mmio-block".equals(value.asString())).count());
        assertTrue(options.stream().anyMatch(value ->
            "/storage/emulated/0/Actual import/iPad (2)/os.img,ro=true,lock=false".equals(value.asString())));
        assertTrue(options.stream().anyMatch(value -> "kind=decoder,uid=12125".equals(value.asString())));
        assertEquals(source.vm.getId(), vm.getId());
        assertEquals(source.vm.getName(), vm.getName());
    }
}
