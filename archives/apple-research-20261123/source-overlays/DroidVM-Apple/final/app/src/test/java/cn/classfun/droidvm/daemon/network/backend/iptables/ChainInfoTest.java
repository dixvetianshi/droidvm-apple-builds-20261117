package cn.classfun.droidvm.daemon.network.backend.iptables;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

/** Exercises the real chain owner without issuing firewall commands. */
public class ChainInfoTest {
    @Test
    public void baseAndPerBridgeChainsShareTheApplicationNamespace() {
        var backend = new IptablesBackend();
        var identity = AppRuntimeIdentity.current();
        var perBridge = new ChainInfo(backend, backend.FIL_FWD, "droidvm_fwd_br1971c95f");
        assertEquals("FORWARD", backend.FIL_FWD.parent);
        assertEquals(identity.firewallChain("droidvm_fwd"), backend.FIL_FWD.chain);
        assertEquals(backend.FIL_FWD.chain, perBridge.parent);
        assertEquals(identity.firewallChain("droidvm_fwd_br1971c95f"), perBridge.chain);
        if (identity.isIsolatedApplication()) {
            assertNotEquals("droidvm_fwd", backend.FIL_FWD.chain);
            assertNotEquals("droidvm_fwd_br1971c95f", perBridge.chain);
        }
    }

    @Test
    public void ipv6ParentKeepsItsAddressFamilyAndResolvedChainName() {
        var backend = new IptablesBackend();
        var perBridge = new ChainInfo(backend, backend.FIL6_FWD, "droidvm_fwd_br1971c95f");
        assertEquals(true, perBridge.ipv6);
        assertEquals("filter", perBridge.table);
        assertEquals(backend.FIL6_FWD.chain, perBridge.parent);
    }
}
