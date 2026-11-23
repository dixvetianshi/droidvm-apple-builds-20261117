package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;
import java.util.Map;

import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile.Guest;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.network.BridgeType;
import cn.classfun.droidvm.lib.store.network.NetworkConfig;
import cn.classfun.droidvm.lib.store.network.NetworkConfigValidator;
import cn.classfun.droidvm.lib.store.network.UplinkMode;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

public final class AppleGuestNetworkProfileTest {
    private static NetworkConfig originalWifi() {
        var config = new NetworkConfig();
        config.setName("Existing Wi-Fi");
        config.setBridgeName("br1971c95f");
        config.setBridgeType(BridgeType.LINUX);
        config.setUplinkMode(UplinkMode.L2);
        config.l2().set("uplink", "WiFi");
        config.l2().set("pseudo_bridge", true);
        config.item.set(NetworkImportPlan.REF_KEY, "apple-uplink");
        return config;
    }

    private static PackageManifest legacyPackage(Guest guest) {
        var manifest = AppleGuestImportProfileTest.verifiedManifest(guest);
        manifest.networks = List.of(originalWifi());
        manifest.vm.item.set("networks", List.of(Map.of(
            NetworkImportPlan.REF_KEY, "apple-uplink", "mac_address", "02:44:56:4d:00:01")));
        return manifest;
    }

    private static NetworkImportPlan applePlan(List<NetworkConfig> existing) {
        return new NetworkImportPlan(existing,
            AppRuntimeIdentity.forApplication("cn.classfun.droidvm.apple"));
    }

    @Test
    public void shippedRecipePassesTheProductionValidatorWithoutChangingDnsOwnership() {
        var network = AppleGuestNetworkProfile.create();
        NetworkConfigValidator.validate(network);
        assertEquals("br-apple-nat", network.getName());
        assertEquals("br-apple-nat", network.getBridgeName());
        assertEquals(BridgeType.GVISOR, network.getBridgeType());
        assertEquals(UplinkMode.L3, network.getUplinkMode());
        assertFalse(network.isAutoUp());
        assertEquals("apple-uplink", network.item.optString(NetworkImportPlan.REF_KEY, ""));
        assertEquals(1, network.getVlans().size());
        var vlan = network.findVlan(0);
        assertNotNull(vlan);
        assertEquals("192.168.237.1/24", vlan.getIpv4Cidr());
        assertTrue(vlan.isIpv4Snat());
        assertTrue(vlan.isDhcp4Enabled());
        assertEquals(128, vlan.getDhcp4OffsetStart());
        assertEquals(192, vlan.getDhcp4OffsetEnd());
        assertTrue(vlan.getDnsServers().isEmpty());
        assertFalse(vlan.isDhcp6Enabled());
        assertFalse(vlan.isSlaacEnabled());
    }

    @Test
    public void bothRecognizedOldPackagesPreviewNatAndRetainTheirSourceAndNic() {
        for (var guest : List.of(Guest.MACOS, Guest.IPADOS)) {
            var manifest = legacyPackage(guest);
            var networkBefore = new DataItem(manifest.networks.get(0).item);
            var vmBefore = new DataItem(manifest.vm.item);
            var projected = NetworkImportPlan.packagedNetworks(manifest);
            assertEquals(1, projected.size());
            assertEquals(BridgeType.GVISOR, projected.get(0).getBridgeType());
            assertEquals("apple-uplink", projected.get(0).item.optString(NetworkImportPlan.REF_KEY, ""));
            assertEquals(networkBefore, manifest.networks.get(0).item);
            assertEquals(vmBefore, manifest.vm.item);
        }
    }

    @Test
    public void aSimilarNameOrDifferentImageDoesNotSelectTheAppleRecommendation() {
        var manifest = legacyPackage(Guest.MACOS);
        manifest.vm.setName("macOS GoldenGate 27.2");
        manifest.disks.get(0).sha256 = "0".repeat(64);
        assertSame(manifest.networks, NetworkImportPlan.packagedNetworks(manifest));
        assertEquals(BridgeType.LINUX, manifest.networks.get(0).getBridgeType());
    }

    @Test
    public void otherRefsAndExplicitRoutedNetworksPreserveCallerValues() {
        var manifest = legacyPackage(Guest.IPADOS);
        var unrelated = originalWifi();
        unrelated.item.set(NetworkImportPlan.REF_KEY, "user-selected-uplink");
        var explicit = AppleGuestNetworkProfile.create();
        explicit.findVlan(0).ipv4().set("cidr", "192.168.76.1/24");
        explicit.findVlan(0).item.set("dns_servers", List.of("192.168.76.2"));
        manifest.networks = List.of(unrelated, explicit);
        var projected = NetworkImportPlan.packagedNetworks(manifest);
        assertSame(unrelated, projected.get(0));
        assertSame(explicit, projected.get(1));
        assertEquals("192.168.76.1/24", projected.get(1).findVlan(0).getIpv4Cidr());
        assertEquals(List.of("192.168.76.2"), projected.get(1).findVlan(0).getDnsServers());
    }

    @Test
    public void existingGvisorL3IsJoinedAndWifiOrLinuxRoutingAreNotCandidates() {
        var wifi = originalWifi();
        var linux = AppleGuestNetworkProfile.create();
        linux.setId("822797b4-e1f6-48e8-ac63-17e947a95507");
        linux.setBridgeType(BridgeType.LINUX);
        linux.setName("Linux routed");
        var existing = AppleGuestNetworkProfile.create();
        existing.setId("822797b4-e1f6-48e8-ac63-17e947a95506");
        existing.setName("Existing gVisor NAT");
        var existingBefore = new DataItem(existing.item);
        var plan = applePlan(List.of(wifi, linux, existing));
        var packaged = NetworkImportPlan.packagedNetworks(legacyPackage(Guest.MACOS)).get(0);
        assertEquals(NetworkImportPlan.Action.JOIN, plan.defaultAction(packaged));
        assertEquals(List.of(existing), plan.candidates(packaged));
        assertEquals(existingBefore, existing.item);
    }

    @Test
    public void noGvisorCandidateCreatesIndependentNatWithTheSameUiAndDaemonConfig() throws Exception {
        var wifi = originalWifi();
        var wifiBefore = new DataItem(wifi.item);
        var packaged = NetworkImportPlan.packagedNetworks(legacyPackage(Guest.IPADOS)).get(0);
        var screenPlan = applePlan(List.of(wifi));
        assertTrue(screenPlan.candidates(packaged).isEmpty());
        assertNull(screenPlan.createConflict(packaged));
        assertEquals(NetworkImportPlan.Action.CREATE, screenPlan.defaultAction(packaged));
        var prepared = screenPlan.prepareCreate(packaged);
        var entry = new NetworkImportPlan.Entry("apple-uplink", NetworkImportPlan.Action.CREATE,
            null, prepared);
        var received = NetworkImportPlan.Entry.fromJson(entry.toJson());
        assertNotNull(received.config);
        var adopted = applePlan(List.of(wifi)).adopt(received.config);
        NetworkConfigValidator.validate(adopted);
        assertEquals(prepared.item, adopted.item);
        assertEquals("br-apple-nat", adopted.getName());
        // The isolated app owns the actual interface name; the recipe's bridge remains provenance.
        assertNotEquals(wifi.getBridgeName(), adopted.getBridgeName());
        assertEquals("br-apple-nat", adopted.item.optString("source_bridge_name", ""));
        assertEquals(wifiBefore, wifi.item);
        assertEquals("apple-uplink", packaged.item.optString(NetworkImportPlan.REF_KEY, ""));
    }
}
