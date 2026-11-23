// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** One reviewed HostShare acquisition at explicit VM start; GPU drivers remain read only. */
final class AppleVmHostCapabilities {
    enum Device { READY, MISSING, UNUSABLE }

    private static final long NODE_PUBLICATION_TIMEOUT_NANOS = 2_000_000_000L;
    private static final long NODE_PUBLICATION_POLL_NANOS = 50_000_000L;

    enum Driver {
        HOST_SHARE("/dev/gunyah_share", "gunyah_host_share_gki_6.6",
            "gunyah-host-share-gki-6.6.ko", 55720,
            "1a9555640c7aee58e26c21baa18780e40c31edb8ae7cdd9009ca67a84892a53f");

        final String node, module, filename, sha256;
        final long bytes;
        Driver(String node, String module, String filename, long bytes, String sha256) {
            this.node = node; this.module = module; this.filename = filename;
            this.bytes = bytes; this.sha256 = sha256;
        }
    }

    interface Host {
        String profileProblem() throws Exception;
        String platformProblem() throws Exception;
        Device device(String exactNode) throws Exception;
        boolean modulePresent(Driver driver) throws Exception;
        boolean privateModuleVerified(Driver driver) throws Exception;
        int insmodWithoutParameters(Driver driver) throws Exception;
        default long monotonicNanos() { return System.nanoTime(); }
        default void sleepNanos(long nanos) throws InterruptedException {
            Thread.sleep(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
        }
    }

    private AppleVmHostCapabilities() {}

    /** Null means ready. A failed or partial acquisition never unloads any kernel module. */
    static String acquireForStart(boolean needShare, boolean needUdmabuf,
                                  boolean phoneLoadAuthorized, Host host) {
        try {
            String problem = host.profileProblem();
            if (problem != null) return problem;
            problem = host.platformProblem();
            if (problem != null) return problem;
            if (needUdmabuf && host.device("/dev/udmabuf") != Device.READY)
                return "Required existing /dev/udmabuf is unavailable; its repair module is not authorized by this plan";
            List<Driver> missing = new ArrayList<>();
            for (Driver driver : Driver.values()) {
                if (!needShare) continue;
                Device state = host.device(driver.node);
                if (state == Device.READY) continue; // includes a usable built-in udmabuf
                if (state != Device.MISSING)
                    return "Existing " + driver.node + " is unusable; it will not be replaced";
                if (host.modulePresent(driver))
                    return driver.module + " is already present but its interface is missing; no reload";
                if (!host.privateModuleVerified(driver))
                    return "App-private driver identity differs from the reviewed " + driver.filename;
                missing.add(driver);
            }
            // Verify the entire small plan before the one authorized HostShare acquisition.
            // The explicit-start adapter owns the separate, narrowly scoped authorization.
            if (!missing.isEmpty() && !phoneLoadAuthorized)
                return "Required interface is missing; this on-demand driver candidate is not enabled";
            for (Driver driver : missing) {
                Device state = host.device(driver.node);
                if (state == Device.READY) continue; // a concurrent provider appeared: only reuse it
                if (state != Device.MISSING || host.modulePresent(driver))
                    return "Driver state changed before acquisition; no reload of " + driver.module;
                int code = host.insmodWithoutParameters(driver);
                long publicationDeadline = host.monotonicNanos() + NODE_PUBLICATION_TIMEOUT_NANOS;
                // Always re-read after insmod, including EEXIST. Never accept an exit code
                // alone, never retry a load, and never replace or unload a foreign provider.
                Device after = host.device(driver.node);
                boolean present = host.modulePresent(driver);
                // Android ueventd can publish the node after module initialization returns.
                // Observe only this just-loaded provider while its node is still missing.
                while (after == Device.MISSING && present) {
                    if (Thread.currentThread().isInterrupted())
                        return loadProblem(driver, code, after, present, "node publication wait interrupted");
                    long remaining = publicationDeadline - host.monotonicNanos();
                    if (remaining <= 0)
                        return loadProblem(driver, code, after, present, "node publication deadline exceeded (2 seconds)");
                    try {
                        host.sleepNanos(Math.min(NODE_PUBLICATION_POLL_NANOS, remaining));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return loadProblem(driver, code, after, present, "node publication wait interrupted");
                    }
                    if (Thread.currentThread().isInterrupted())
                        return loadProblem(driver, code, after, present, "node publication wait interrupted");
                    if (publicationDeadline - host.monotonicNanos() <= 0)
                        return loadProblem(driver, code, after, present, "node publication deadline exceeded (2 seconds)");
                    after = host.device(driver.node);
                    if (after == Device.UNUSABLE) break;
                    if (Thread.currentThread().isInterrupted())
                        return loadProblem(driver, code, after, present, "node publication wait interrupted");
                    if (publicationDeadline - host.monotonicNanos() <= 0)
                        return loadProblem(driver, code, after, present, "node publication deadline exceeded (2 seconds)");
                    present = host.modulePresent(driver);
                    if (!present) break;
                    if (Thread.currentThread().isInterrupted())
                        return loadProblem(driver, code, after, present, "node publication wait interrupted");
                    if (publicationDeadline - host.monotonicNanos() <= 0)
                        return loadProblem(driver, code, after, present, "node publication deadline exceeded (2 seconds)");
                }
                if (after != Device.READY || !present)
                    return loadProblem(driver, code, after, present, null);
            }
            return null;
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return "Required host capability could not be verified (" + e.getClass().getSimpleName() + ")";
        }
    }

    private static String loadProblem(Driver driver, int code, Device after, boolean present, String detail) {
        return "Required " + driver.node + " is unavailable after one driver load (exit " + code
            + ", after=" + after + ", present=" + present + (detail == null ? "" : ", " + detail) + ")";
    }

    /** The exact enabled values accepted by the frozen native reserve owner. */
    static boolean permittedReserveHook(String raw) {
        return raw != null && (raw.trim().equals("1") || raw.trim().equals("Y"));
    }

    /** Native ReadOnly accepts 'never' only after strict pin proof; 'deny' is forbidden. */
    static boolean permittedShmemPolicy(String raw) {
        if (raw == null) return false;
        String selected = null;
        for (String token : raw.trim().split("\\s+")) {
            if (token.startsWith("[") && token.endsWith("]")) {
                if (selected != null) return false;
                selected = token.substring(1, token.length() - 1);
            }
        }
        return Set.of("always", "within_size", "advise", "never", "force").contains(selected == null ? "" : selected);
    }
}
