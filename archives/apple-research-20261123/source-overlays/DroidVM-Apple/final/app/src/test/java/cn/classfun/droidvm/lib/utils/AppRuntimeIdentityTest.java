package cn.classfun.droidvm.lib.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AppRuntimeIdentityTest {
    private static final AppRuntimeIdentity ORIGINAL = AppRuntimeIdentity
        .forApplication("cn.classfun.droidvm");
    private static final AppRuntimeIdentity APPLE = AppRuntimeIdentity
        .forApplication("cn.classfun.droidvm.apple");

    @Test
    public void applicationVariantsHaveDifferentFirewallChainsAndGpuGroups() {
        var chain = APPLE.firewallChain("droidvm_fwd");
        assertNotEquals(ORIGINAL.firewallChain("droidvm_fwd"), chain);
        assertNotEquals(APPLE.gpuCgroupPath(""), ORIGINAL.gpuCgroupPath(""));
        assertNotEquals(chain, AppRuntimeIdentity.forApplication("cn.classfun.droidvm.other")
            .firewallChain("droidvm_fwd"));
        assertEquals("FORWARD", APPLE.firewallChain("FORWARD"));
        assertEquals(chain, APPLE.firewallChain(chain));
    }

    @Test
    public void bridgeAndPerNetworkChainNamesFitActualKernelLimits() {
        var id = "5e3dcd75-c8c1-47e5-85b8-4d4436c02803";
        var bridge = APPLE.bridgeName(id);
        assertEquals(12, bridge.length());
        assertTrue(bridge.matches("[a-zA-Z][a-zA-Z0-9_-]*"));
        assertTrue((bridge + "vAB").length() <= 15);
        assertTrue(APPLE.firewallChain("droidvm_fwd_" + bridge).length() <= 28);
        assertEquals(bridge, APPLE.bridgeName(id));
        assertNotEquals(bridge, APPLE.bridgeName("695103ac-de77-4930-9965-e9a4f36a8385"));
        assertNotEquals(bridge, ORIGINAL.bridgeName(id));
    }

    @Test
    public void oldSharedGpuDefaultMigratesWhileExplicitPathSurvives() {
        assertEquals(APPLE.gpuCgroupPath(""), APPLE.gpuCgroupPath(" /dev/cpuset/gpuworker "));
        assertEquals("/dev/cpuset/gpuworker", ORIGINAL.gpuCgroupPath(""));
        assertEquals("/dev/cpuset/my_gpu", APPLE.gpuCgroupPath("/dev/cpuset/my_gpu"));
        assertFalse(APPLE.gpuCgroupPath("").equals("/dev/cpuset/gpuworker"));
    }

    @Test
    public void executablePatternCannotSelectOriginalAppOrAPathInsideArguments() {
        var executable = "/data/data/cn.classfun.droidvm.apple/bin/pbridge";
        // Java uses Unicode property notation for the same POSIX whitespace
        // boundary; the production pattern is passed unchanged to pkill's ERE.
        var pattern = AppRuntimeIdentity.executableCommandPattern(executable)
            .replace("[[:space:]]", "\\s");
        assertTrue((executable + " --uplink wlan0").matches(pattern + ".*"));
        assertTrue(executable.matches(pattern));
        assertFalse("/data/data/cn.classfun.droidvm/bin/pbridge --uplink wlan0"
            .matches(pattern + ".*"));
        assertFalse((executable + "-unrelated").matches(pattern + ".*"));
        assertFalse(("/system/bin/sh -c " + executable).matches(pattern + ".*"));
        assertFalse("/data/data/cnXclassfunXdroidvmXapple/bin/pbridge".matches(pattern));
    }

    @Test
    public void appleNeverManagesSharedHostStateAndOwnsOnlyItsDefaultGpuGroup() {
        assertFalse(APPLE.allowsSharedHostMutation());
        assertTrue(ORIGINAL.allowsSharedHostMutation());
        assertTrue(APPLE.ownsGpuCgroupPath(APPLE.gpuCgroupPath("")));
        assertFalse(APPLE.ownsGpuCgroupPath("/dev/cpuset/gpuworker"));
        assertFalse(APPLE.ownsGpuCgroupPath("/dev/cpuset/my_gpu"));
    }

    @Test
    public void vmTapNamesAreStableNamespacedAndFitKernelLimits() {
        var vmId = "5e3dcd75-c8c1-47e5-85b8-4d4436c02803";
        var name = APPLE.tapName(vmId, 0);
        assertEquals(15, name.length());
        assertEquals(name, APPLE.tapName(vmId, 0));
        assertNotEquals(name, APPLE.tapName(vmId, 1));
        assertNotEquals(name, ORIGINAL.tapName(vmId, 0));
        assertTrue(APPLE.ownsTapName(name));
        assertFalse(APPLE.ownsTapName("vm5e3dcd75-0"));
        assertFalse(APPLE.ownsTapName(ORIGINAL.tapName(vmId, 0)));
        assertFalse(APPLE.ownsTapName(name + "x"));
    }
}
