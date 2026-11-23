// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon;

import static android.os.Process.myPid;
import static cn.classfun.droidvm.BuildConfig.APPLICATION_ID;
import static cn.classfun.droidvm.lib.Constants.DATA_DIR;
import static cn.classfun.droidvm.lib.daemon.DaemonHelper.getPidFile;
import static cn.classfun.droidvm.lib.daemon.DaemonHelper.getPortFile;
import static cn.classfun.droidvm.lib.daemon.DaemonHelper.getTokenFile;
import static cn.classfun.droidvm.lib.utils.FileUtils.findExecute;
import static cn.classfun.droidvm.lib.utils.FileUtils.writeFile;
import static cn.classfun.droidvm.lib.utils.RunUtils.runList;
import static cn.classfun.droidvm.lib.utils.StringUtils.fmt;
import static cn.classfun.droidvm.lib.utils.StringUtils.pathJoin;

import android.system.Os;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import cn.classfun.droidvm.daemon.audio.HostAudioTable;
import cn.classfun.droidvm.daemon.display.DaemonSystemContext;
import cn.classfun.droidvm.daemon.server.Server;
import cn.classfun.droidvm.lib.daemon.DaemonOwnership;
import cn.classfun.droidvm.lib.natives.UnixHelper;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;
import cn.classfun.droidvm.lib.utils.FileUtils;
import cn.classfun.droidvm.lib.utils.ProcessUtils;

public final class Daemon {
    public static final String TAG = "Daemon";
    public static final String LOG_PATH = pathJoin(DATA_DIR, "cache", "daemon.log");
    private static final String RUN_DIR = pathJoin(DATA_DIR, "run");
    private static final String LOCK_FILE = pathJoin(RUN_DIR, "droidvmd.lock");
    private static final AtomicBoolean cleaned = new AtomicBoolean(false);
    public static String daemonHash = null;
    private static Process logcatProcess = null;

    // Held for the whole process lifetime so the advisory lock stays taken; the
    // kernel drops it automatically when this process dies (including SIGKILL),
    // so a stale lock can never block the next daemon.
    @SuppressWarnings("FieldCanBeLocal")
    private static FileChannel lockChannel;
    @SuppressWarnings("FieldCanBeLocal")
    private static FileLock daemonLock;
    private static DaemonOwnership.Owner daemonOwner;

    /**
     * Single-instance gate. Tries to take an exclusive lock on
     * {@code droidvmd.lock}. Returns true when held by this process. When the
     * lock is already taken by a live daemon: with {@code force}, that daemon
     * is asked to exit with SIGINT and the lock is taken over after it exits.
     * An isolated application never escalates to SIGKILL while its VMs may
     * still be releasing shared memory; legacy takeover keeps its escalation.
     * without it, this returns false so the caller exits instead of running a
     * second daemon.
     */
    private static boolean acquireLock(boolean force) {
        var runDir = new File(RUN_DIR);
        if (!runDir.exists() && !runDir.mkdirs())
            Log.w(TAG, fmt("Failed to create run directory: %s", runDir));
        try {
            lockChannel = FileChannel.open(Paths.get(LOCK_FILE),
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } catch (IOException e) {
            Log.e(TAG, fmt("Failed to open lock file: %s", LOCK_FILE), e);
            return false;
        }
        if (tryLock()) {
            return writeLockOwner();
        }
        int holder = readLockOwner();
        if (!force) {
            Log.e(TAG, fmt(
                "Another daemon (pid=%d) is already running; exiting "
                    + "(start with --force to take over)", holder));
            return false;
        }
        boolean isolated = AppRuntimeIdentity.current().isIsolatedApplication();
        Log.i(TAG, fmt("--force: requesting existing daemon shutdown (pid=%d)", holder));
        if (isolated) {
            if (!DaemonOwnership.signalIfOwned(holder, ProcessUtils.SIGINT)) return false;
        } else if (holder > 1) {
            ProcessUtils.shellKillProcess(holder, ProcessUtils.SIGINT);
        }
        if (waitForLock(10_000)) {
            return writeLockOwner();
        }
        if (isolated) {
            Log.w(TAG, fmt("Existing Apple daemon (pid=%d) is still shutting down; "
                + "waiting for its VM cleanup before any later takeover", holder));
            return false;
        }
        if (holder > 1) {
            Log.w(TAG, fmt("Existing daemon (pid=%d) did not exit; sending SIGKILL", holder));
            ProcessUtils.shellKillProcess(holder, ProcessUtils.SIGKILL);
        }
        if (waitForLock(3_000)) {
            return writeLockOwner();
        }
        Log.e(TAG, "Failed to take over the daemon lock");
        return false;
    }

    private static boolean tryLock() {
        try {
            daemonLock = lockChannel.tryLock();
            return daemonLock != null;
        } catch (Exception e) {
            // OverlappingFileLockException can't happen (single attempt); any
            // other failure is treated as "not acquired".
            Log.w(TAG, "tryLock failed", e);
            return false;
        }
    }

    private static boolean waitForLock(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (tryLock()) return true;
            try {
                //noinspection BusyWait
                Thread.sleep(200);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return false;
    }

    /** Publishes the PID and isolated process identity while holding the daemon lock. */
    private static boolean writeLockOwner() {
        try {
            lockChannel.truncate(0);
            lockChannel.position(0);
            lockChannel.write(ByteBuffer.wrap(String.valueOf(myPid()).getBytes()));
            lockChannel.force(false);
            if (AppRuntimeIdentity.current().isIsolatedApplication())
                daemonOwner = DaemonOwnership.publishCurrent();
            return true;
        } catch (IOException e) {
            Log.w(TAG, "Failed to publish lock owner", e);
            return !AppRuntimeIdentity.current().isIsolatedApplication();
        }
    }

    /** Pid of the current lock holder: from the lock file, else the pid file. */
    private static int readLockOwner() {
        for (var path : new String[]{LOCK_FILE, getPidFile()}) {
            try {
                var s = FileUtils.readFile(path).trim();
                if (!s.isEmpty()) return Integer.parseInt(s);
            } catch (Exception ignored) {
            }
        }
        return -1;
    }

    private static void writePidFile() {
        var runDir = new File(RUN_DIR);
        if (!runDir.exists() && !runDir.mkdirs())
            Log.w(TAG, fmt("Failed to create run directory: %s", runDir));
        var pidFile = new File(runDir, "droidvmd.pid");
        try (var writer = new FileWriter(pidFile)) {
            writer.write(String.valueOf(myPid()));
            writer.flush();
            Log.i(TAG, fmt("PID file written: %s (pid=%d)", pidFile, myPid()));
        } catch (IOException e) {
            Log.e(TAG, fmt("Failed to write PID file: %s", pidFile), e);
        }
    }

    private static void writeTokenFile() {
        var runDir = new File(RUN_DIR);
        if (!runDir.exists() && !runDir.mkdirs())
            Log.w(TAG, fmt("Failed to create run directory: %s", runDir));
        var tokenFile = new File(runDir, "droidvmd-token.txt");
        var token = UUID.randomUUID().toString().replace("-", "");
        try (var writer = new FileWriter(tokenFile)) {
            writer.write(token);
            writer.flush();
            Log.i(TAG, fmt("Token file written: %s", tokenFile));
        } catch (IOException e) {
            Log.e(TAG, fmt("Failed to write token file: %s", tokenFile), e);
        }
    }

    private static void cleanup(Server server) {
        if (!cleaned.compareAndSet(false, true)) return;
        Log.i(TAG, "Stopping all VMs and networks...");
        var ctx = server.getContext();
        try {
            ctx.getVMs().shutdownAll();
        } finally {
            // After the VMs, not before: stopping them only queues the USB releases, and the
            // interfaces are handed back to the host from that queue. In a finally, because the
            // first thing that shutdown does is put /sys/bus/usb/drivers_autoprobe back to the
            // kernel's default: that flag is global and outlives this process, so a stop that
            // throws on its way past here would leave every device plugged into the phone
            // afterwards with no driver bound -- no keyboard, no storage -- and no daemon left
            // to write it back.
            ctx.getUsb().shutdown();
        }
        ctx.getNetworks().stopAll();
        ctx.getNetworks().firewall.shutdown();
        ctx.getRouterWatcher().stop();
        removeControlFilesIfOwned();
        Log.i(TAG, "DroidVM Daemon shutdown complete");
    }

    private static void removeControlFilesIfOwned() {
        if (!AppRuntimeIdentity.current().isIsolatedApplication()
            || DaemonOwnership.removeIfOwned(daemonOwner)) {
            FileUtils.deleteFile(getPidFile());
            FileUtils.deleteFile(getTokenFile());
            FileUtils.deleteFile(getPortFile());
        }
    }

    @NonNull
    private static String getMyHash() {
        var pmResult = runList("pm", "path", APPLICATION_ID);
        if (!pmResult.isSuccess()) {
            pmResult.printLog(TAG);
            throw new RuntimeException(fmt("Failed to get package path"));
        }
        var pkgPath = pmResult.getOutString().trim();
        if (!pkgPath.startsWith("package:"))
            throw new RuntimeException(fmt("Unexpected pm output: %s", pkgPath));
        pkgPath = pkgPath.substring("package:".length()).trim();
        if (!new File(pkgPath).exists())
            throw new RuntimeException(fmt("Package path does not exist: %s", pkgPath));
        try {
            var hash = FileUtils.calcHashForFile(pkgPath, "SHA-256");
            if (hash.length() != 64)
                throw new RuntimeException(fmt("Unexpected hash length: %d", hash.length()));
            return hash;
        } catch (Exception e) {
            throw new RuntimeException(fmt("Failed to calculate hash for package: %s", pkgPath), e);
        }
    }

    private static void setProcTitle() {
        try {
            FileUtils.writeFile("/proc/self/comm", "droidvmd");
        } catch (IOException e) {
            Log.w(TAG, "Failed to set process title", e);
        }
    }

    @SuppressWarnings("OctalInteger")
    private static void startLogcat() {
        try {
            var builder = new ProcessBuilder();
            var file = new File(LOG_PATH);
            if (file.exists() && !file.delete())
                Log.w(TAG, "failed to remove old log");
            writeFile(file, "");
            var uid = Server.getDroidVMUid();
            Os.chmod(LOG_PATH, 0600);
            Os.chown(LOG_PATH, uid, uid);
            builder.command(
                findExecute("logcat", "/system/bin/logcat"),
                fmt("--pid=%d", myPid())
            );
            builder.redirectOutput(new File(LOG_PATH));
            logcatProcess = builder.start();
        } catch (Exception e) {
            Log.w(TAG, "failed to start logcat", e);
            logcatProcess = null;
        }
    }

    private static void stopLogcat() {
        if (logcatProcess == null) return;
        logcatProcess.destroy();
        logcatProcess = null;
    }

    public static void main(String... args) {
        boolean force = Arrays.asList(args).contains("--force");
        System.out.print("Starting DroidVM Daemon...\n");
        UnixHelper.load();
        // Build a system Context on the main thread (it prepares the main looper) so the daemon can
        // broadcast the native-display binder to the UI. Must happen before server.run() blocks here.
        DaemonSystemContext.init();
        setProcTitle();
        System.out.printf("Current pid: %d\n", myPid());
        Log.d(TAG, "DroidVM Daemon is starting...");
        if (!acquireLock(force)) {
            System.out.print("Another DroidVM Daemon is already running.\n");
            System.exit(1);
        }
        final Server server;
        try {
            // Publish audio endpoints before any VM starts and track headset reconnections.
            HostAudioTable.start(DaemonSystemContext.get());
            daemonHash = getMyHash();
            Log.i(TAG, fmt("DroidVM Daemon hash: %s", daemonHash));
            server = new Server();
        } catch (RuntimeException | Error e) {
            removeControlFilesIfOwned();
            throw e;
        }
        writePidFile();
        writeTokenFile();
        UnixHelper.installSignalHandler("INT", sig -> {
            Log.i(TAG, fmt("Received signal %d (INT), shutting down...", sig));
            System.exit(128 + sig);
        });
        UnixHelper.installSignalHandler("TERM", sig -> {
            Log.i(TAG, fmt("Received signal %d (TERM), shutting down...", sig));
            System.exit(128 + sig);
        });
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                server.stop();
                cleanup(server);
            } finally {
                stopLogcat();
            }
        }));
        // Failed lock attempts preserve the running daemon's log and start no logcat child.
        startLogcat();
        try {
            server.run();
            cleanup(server);
        } finally {
            stopLogcat();
        }
    }
}
