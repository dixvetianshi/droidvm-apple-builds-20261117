// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.lib.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.UUID;

import cn.classfun.droidvm.BuildConfig;

/** Names the host resources that cannot live inside an application's private directory. */
public final class AppRuntimeIdentity {
    public static final String ORIGINAL_APPLICATION_ID = "cn.classfun.droidvm";
    public static final String LEGACY_GPU_CGROUP_PATH = "/dev/cpuset/gpuworker";
    private static final String ORIGINAL_CHAIN_PREFIX = "droidvm_";
    private static final AppRuntimeIdentity CURRENT = forApplication(BuildConfig.APPLICATION_ID);

    private final String applicationId;
    private final String hostPrefix;

    private AppRuntimeIdentity(String applicationId) {
        this.applicationId = Objects.requireNonNull(applicationId);
        if (!applicationId.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
            throw new IllegalArgumentException("Invalid application ID");
        // Ten characters plus '_' leaves room for fwd_<12-char bridge> in a
        // legacy iptables chain name, whose usable name limit is 28 bytes.
        hostPrefix = "dv" + hash(applicationId).substring(0, 8);
    }

    public static AppRuntimeIdentity forApplication(String applicationId) {
        return new AppRuntimeIdentity(applicationId);
    }

    public static AppRuntimeIdentity current() {
        return CURRENT;
    }

    public boolean isIsolatedApplication() {
        return !ORIGINAL_APPLICATION_ID.equals(applicationId);
    }

    /** The standalone app consumes existing host capabilities; it does not manage shared ones. */
    public boolean allowsSharedHostMutation() {
        return !isIsolatedApplication();
    }

    public String sharedHostReadOnlyReason() {
        return "DroidVM Apple only reads existing host capabilities; shared kernel, memory "
            + "and host network changes are disabled";
    }

    /** One namespaced TAP per local VM NIC; stored legacy names cannot select another app's TAP. */
    public String tapName(String vmId, int nicIndex) {
        if (nicIndex < 0) throw new IllegalArgumentException("Invalid NIC index");
        var id = UUID.fromString(vmId).toString();
        return hostPrefix.substring(0, 6) + "t"
            + hash(applicationId + "\0" + id + "\0" + nicIndex).substring(0, 8);
    }

    public boolean ownsTapName(String name) {
        return name != null && name.matches(hostPrefix.substring(0, 6) + "t[0-9a-f]{8}");
    }

    public boolean ownsGpuCgroupPath(String path) {
        return gpuCgroupPath("").equals(path);
    }

    /** Maps our own logical chain names once; built-in targets and parents remain literal. */
    public String firewallChain(String logicalName) {
        if (logicalName == null || !isIsolatedApplication()
            || !logicalName.startsWith(ORIGINAL_CHAIN_PREFIX)) return logicalName;
        return hostPrefix + "_" + logicalName.substring(ORIGINAL_CHAIN_PREFIX.length());
    }

    /** A stable bridge for one imported network, including its future three-byte VLAN suffix. */
    public String bridgeName(String networkId) {
        var id = UUID.fromString(networkId).toString();
        return "ap" + hash(applicationId + "\0" + id).substring(0, 10);
    }

    /** Migrates the original shared default; explicitly chosen non-default paths remain choices. */
    public String gpuCgroupPath(String requested) {
        var path = requested == null ? "" : requested.trim();
        if (path.isEmpty() || LEGACY_GPU_CGROUP_PATH.equals(path))
            return isIsolatedApplication()
                ? "/dev/cpuset/" + hostPrefix + "_gpu" : LEGACY_GPU_CGROUP_PATH;
        return path;
    }

    /** POSIX ERE for one exact executable in argv[0], never a path appearing in an argument. */
    public static String executableCommandPattern(String executable) {
        if (executable == null || !executable.startsWith("/") || executable.indexOf('\n') >= 0
            || executable.indexOf('\r') >= 0 || executable.indexOf('\0') >= 0)
            throw new IllegalArgumentException("An absolute executable path is required");
        var escaped = new StringBuilder("^");
        for (int i = 0; i < executable.length(); i++) {
            char value = executable.charAt(i);
            if ("\\.^$|?*+(){}[]".indexOf(value) >= 0) escaped.append('\\');
            escaped.append(value);
        }
        return escaped.append("([[:space:]]|$)").toString();
    }

    private static String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            var hex = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                hex.append(Character.forDigit((item >>> 4) & 15, 16));
                hex.append(Character.forDigit(item & 15, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime", e);
        }
    }
}
