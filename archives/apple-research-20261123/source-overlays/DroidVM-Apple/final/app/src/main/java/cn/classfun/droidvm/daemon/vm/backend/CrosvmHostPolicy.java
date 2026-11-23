// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm.backend;

import java.util.List;

import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;
import cn.classfun.droidvm.lib.store.vm.VMBackend;

/** Owns the standalone app's crosvm run policy and reserves its typed host settings. */
public final class CrosvmHostPolicy {
    private CrosvmHostPolicy() {}

    public static void appendRunArguments(List<String> args, AppRuntimeIdentity identity) {
        if (!identity.isIsolatedApplication()) return;
        args.add("--host-memory-policy");
        args.add("read-only");
    }

    public static void validateExtraArguments(List<String> args, AppRuntimeIdentity identity) {
        if (!identity.isIsolatedApplication()) return;
        for (var arg : args) {
            var separator = arg.indexOf('=');
            var option = separator < 0 ? arg : arg.substring(0, separator);
            if (option.equals("--host-memory-policy") || option.equals("--gpu-cgroup-path")
                || option.equals("--vcpu-cgroup-path") || option.equals("--cpu-freq-domains")
                || option.equals("--cfg") || option.equals("--kms-display"))
                throw new IllegalArgumentException("DroidVM Apple reserves " + option
                    + " for its host isolation policy; remove it from extra options");
        }
    }

    public static void validateBackend(VMBackend backend, AppRuntimeIdentity identity) {
        if (identity.isIsolatedApplication() && backend != VMBackend.CROSVM)
            throw new IllegalArgumentException("DroidVM Apple cannot start this backend: "
                + "only crosvm currently supports its host read-only policy");
    }
}
