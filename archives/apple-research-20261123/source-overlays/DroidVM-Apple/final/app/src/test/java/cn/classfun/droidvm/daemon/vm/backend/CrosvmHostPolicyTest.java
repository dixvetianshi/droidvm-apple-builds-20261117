package cn.classfun.droidvm.daemon.vm.backend;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import cn.classfun.droidvm.lib.store.vm.VMBackend;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

public final class CrosvmHostPolicyTest {
    private static final AppRuntimeIdentity APPLE = AppRuntimeIdentity.forApplication("cn.classfun.droidvm.apple");
    private static final AppRuntimeIdentity ORIGINAL = AppRuntimeIdentity.forApplication("cn.classfun.droidvm");

    @Test
    public void appleRequestsReadOnlyWhileOriginalKeepsItsNativeDefault() {
        var appleArgs = new ArrayList<String>();
        CrosvmHostPolicy.appendRunArguments(appleArgs, APPLE);
        assertEquals(List.of("--host-memory-policy", "read-only"), appleArgs);
        var originalArgs = new ArrayList<String>();
        CrosvmHostPolicy.appendRunArguments(originalArgs, ORIGINAL);
        assertEquals(List.of(), originalArgs);
    }

    @Test
    public void rawArgumentsCannotOverrideApplePolicyOrCgroupOwnership() {
        for (var option : List.of("--host-memory-policy", "--gpu-cgroup-path",
            "--vcpu-cgroup-path", "--cpu-freq-domains", "--cfg", "--kms-display")) {
            assertThrows(IllegalArgumentException.class, () ->
                CrosvmHostPolicy.validateExtraArguments(List.of(option, "value"), APPLE));
            assertThrows(IllegalArgumentException.class, () ->
                CrosvmHostPolicy.validateExtraArguments(List.of(option + "=value"), APPLE));
            CrosvmHostPolicy.validateExtraArguments(List.of(option, "value"), ORIGINAL);
        }
    }

    @Test
    public void mediaAndOrdinaryExtraArgumentsRemainCallerChoices() {
        CrosvmHostPolicy.validateExtraArguments(List.of("--virtio-media", "value", "--disk", "disk.img"), APPLE);
    }

    @Test
    public void onlyCrosvmHasAnAppleHostReadOnlyPolicy() {
        CrosvmHostPolicy.validateBackend(VMBackend.CROSVM, APPLE);
        assertThrows(IllegalArgumentException.class, () -> CrosvmHostPolicy.validateBackend(VMBackend.QEMU, APPLE));
        CrosvmHostPolicy.validateBackend(VMBackend.QEMU, ORIGINAL);
    }
}
