package cn.classfun.droidvm.daemon.network.backend.gvisor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import cn.classfun.droidvm.lib.pkg.AppleGuestNetworkProfile;

/** The packaged recipe reaches the actual backend's DHCP, routing and Android DNS projection. */
public final class AppleGuestGvswitchConfigTest {
    @Test
    public void natRecipeEnablesDhcpAndInternetRoutingWithTheAndroidDnsProxy() throws Exception {
        var runtime = GvswitchConfigBuilder.build(AppleGuestNetworkProfile.create());
        var gateways = runtime.getJSONArray("gateways");
        assertEquals(1, gateways.length());
        var gateway = gateways.getJSONObject(0);
        assertEquals(0, gateway.getInt("vlan"));
        assertTrue(gateway.getBoolean("enable_internet_routing"));
        assertTrue(gateway.getBoolean("dns_proxy"));
        assertEquals("192.168.237.1", gateway.getJSONObject("ipv4").getString("address"));
        assertEquals(24, gateway.getJSONObject("ipv4").getInt("prefix_len"));
        var dhcp = gateway.getJSONObject("dhcp4");
        assertTrue(dhcp.getBoolean("enabled"));
        assertEquals("192.168.237.128", dhcp.getString("pool_start"));
        assertEquals("192.168.237.192", dhcp.getString("pool_end"));
        assertFalse(dhcp.has("dns"));
        assertFalse(gateway.has("dhcp6"));
        assertEquals("[::]/0", gateway.getJSONArray("deny").getString(0));
    }
}
