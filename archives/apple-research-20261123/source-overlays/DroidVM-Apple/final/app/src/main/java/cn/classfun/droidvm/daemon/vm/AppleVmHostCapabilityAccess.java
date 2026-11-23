// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm;

import static cn.classfun.droidvm.lib.store.enums.Enums.optEnum;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import cn.classfun.droidvm.BuildConfig;
import cn.classfun.droidvm.daemon.display.DaemonSystemContext;
import cn.classfun.droidvm.lib.Constants;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.vm.ProtectedVM;
import cn.classfun.droidvm.lib.store.vm.VMBackend;
import cn.classfun.droidvm.lib.store.vm.VMHypervisor;
import cn.classfun.droidvm.lib.store.vm.VMScreenConfig;
import cn.classfun.droidvm.lib.utils.RunUtils;

/** Root I/O adapter for the one authorized HostShare acquisition at explicit VM start. */
final class AppleVmHostCapabilityAccess implements AppleVmHostCapabilities.Host {
    // Authorized only for the reviewed HostShare component when its interface is absent.
    // This is not a preference, autostart choice, environment variable or global gate.
    private static final boolean PHONE_LOAD_AUTHORIZED = true;
    private static final String APP = "cn.classfun.droidvm.apple";
    private static final String APP_DIR = "/data/data/" + APP;
    private static final String MODULES = APP_DIR + "/usr/lib/modules/android15-6.6/";
    private int reviewedAppUid = -1;
    private static final String BTF_SHA256 =
        "2cdedf988e90c204b603db7e4b45eda0c10513ce692f27104ce745850e279741";

    private AppleVmHostCapabilityAccess() {}

    static String acquireForVmStart(DataItem item) {
        VMBackend backend = optEnum(item, "backend", VMBackend.DEFAULT);
        VMHypervisor configured = optEnum(item, "hypervisor", VMHypervisor.DEFAULT);
        if (backend != VMBackend.CROSVM
            || VMHypervisor.resolveConfigured(backend, configured) != VMHypervisor.GUNYAH) return null;
        boolean gpu = VMScreenConfig.hasGpuDevice(item);
        // A simplefb-only GPU blit is optional and already falls back to CPU when udmabuf
        // is unavailable. It does not authorize a driver load or become a new start guard.
        // The captured Mac/iPad virtio-gpu configurations require the udmabuf interface.
        boolean share = optEnum(item, "protected_vm", ProtectedVM.PROTECTED_WITHOUT_FIRMWARE)
            == ProtectedVM.PSEUDO_UNPROTECTED || gpu;
        return AppleVmHostCapabilities.acquireForStart(share, gpu, PHONE_LOAD_AUTHORIZED,
            new AppleVmHostCapabilityAccess());
    }

    @Override public String profileProblem() throws Exception {
        if (!BuildConfig.APPLICATION_ID.equals(APP) || !Constants.DATA_DIR.equals(APP_DIR))
            return "On-demand capability review applies only to the installed Apple package";
        int appUid = DaemonSystemContext.get().getPackageManager().getApplicationInfo(APP, 0).uid;
        if (appUid < 10000)
            return "Installed Apple package ownership could not be verified";
        var root = Os.lstat(APP_DIR);
        if (!OsConstants.S_ISDIR(root.st_mode) || root.st_uid != appUid || root.st_gid != appUid
            || (root.st_mode & 07777) != 0700)
            return "Installed Apple data-directory identity differs from this reviewed profile";
        String release = command("uname", "-r");
        if (!release.startsWith("6.6.") || !release.contains("-android15-"))
            return "No exact Android15 6.6 KMI driver review applies to this kernel";
        String vendor = command("getprop", "ro.soc.manufacturer");
        if (!(vendor.equalsIgnoreCase("QTI") || vendor.equalsIgnoreCase("Qualcomm"))
            || !command("getprop", "ro.soc.model").equals("SM8750")
            || !command("getprop", "ro.board.platform").equals("sun"))
            return "On-demand driver review requires the observed SM8750/sun platform";
        if (!sha256(new File("/sys/kernel/btf/vmlinux")).equals(BTF_SHA256))
            return "Running-kernel BTF identity differs; no driver is loaded";
        reviewedAppUid = appUid;
        return null;
    }

    @Override public String platformProblem() throws Exception {
        // No private .ko in this plan provides these platform capabilities. PoolPreflight
        // already verified reserve capacity before this method. No script or knob is written.
        for (String node : new String[]{"/dev/gunyah", "/dev/gh_pinprobe"})
            if (device(node) != AppleVmHostCapabilities.Device.READY)
                return "Required existing platform interface " + node + " is unavailable; it cannot be acquired by this plan";
        if (!AppleVmHostCapabilities.permittedReserveHook(
            readText("/sys/module/gh_hugepage_reserve/parameters/hook_enable")))
            return "Existing huge-page reserve hook is disabled; no parameters are changed";
        if (!AppleVmHostCapabilities.permittedShmemPolicy(
            readText("/sys/kernel/mm/transparent_hugepage/shmem_enabled")))
            return "Existing shmem policy forbids or cannot verify ReadOnly memory preparation";
        return null;
    }

    @Override public AppleVmHostCapabilities.Device device(String path) throws Exception {
        try {
            var state = Os.lstat(path);
            return OsConstants.S_ISCHR(state.st_mode) && Os.access(path, OsConstants.R_OK | OsConstants.W_OK)
                ? AppleVmHostCapabilities.Device.READY : AppleVmHostCapabilities.Device.UNUSABLE;
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.ENOENT) return AppleVmHostCapabilities.Device.MISSING;
            throw e; // permission/read failure is unknown, not a missing driver
        }
    }

    @Override public boolean modulePresent(AppleVmHostCapabilities.Driver driver) throws Exception {
        for (String line : command("cat", "/proc/modules").split("\\n")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 6 && !line.trim().isEmpty()) throw new IOException("Invalid module inventory");
            if (fields.length >= 6 && fields[0].equals(driver.module)) return true;
        }
        return false;
    }

    @Override public boolean privateModuleVerified(AppleVmHostCapabilities.Driver driver) throws Exception {
        if (reviewedAppUid < 10000) return false;
        File file = new File(MODULES + driver.filename);
        var state = Os.lstat(file.getPath());
        return OsConstants.S_ISREG(state.st_mode) && state.st_uid == reviewedAppUid && state.st_gid == reviewedAppUid
            && (state.st_mode & 07777) == 0644 && state.st_size == driver.bytes
            && file.getCanonicalPath().equals(file.getPath()) && sha256(file).equals(driver.sha256);
    }

    @Override public int insmodWithoutParameters(AppleVmHostCapabilities.Driver driver) {
        // Only the fixed HostShare filename. No Udmabuf repair, caller path or parameters.
        return RunUtils.runList("insmod", MODULES + driver.filename).getCode();
    }

    private static String command(String... args) throws IOException {
        var result = RunUtils.runListQuiet(args);
        if (!result.isSuccess()) throw new IOException("Required metadata command failed");
        return result.getOutString().trim();
    }

    private static String readText(String path) throws IOException {
        try (var input = new FileInputStream(path)) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = new FileInputStream(file)) {
            byte[] buffer = new byte[65536];
            for (int n; (n = input.read(buffer)) >= 0;) if (n > 0) digest.update(buffer, 0, n);
        }
        StringBuilder out = new StringBuilder(64);
        for (byte b : digest.digest()) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
}
