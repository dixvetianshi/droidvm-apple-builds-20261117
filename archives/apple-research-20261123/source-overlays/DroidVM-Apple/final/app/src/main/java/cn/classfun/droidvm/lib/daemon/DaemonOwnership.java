// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.daemon;

import static cn.classfun.droidvm.BuildConfig.APPLICATION_ID;
import static cn.classfun.droidvm.lib.Constants.DATA_DIR;
import static cn.classfun.droidvm.lib.utils.StringUtils.pathJoin;

import android.os.Process;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import cn.classfun.droidvm.lib.run.RunResult;
import cn.classfun.droidvm.lib.utils.FileUtils;
import cn.classfun.droidvm.lib.utils.ProcessUtils;
import cn.classfun.droidvm.lib.utils.RunUtils;

/** Identity of one daemon process; a numeric PID or a shared process name is not ownership. */
public final class DaemonOwnership {
    private static final String TAG = "DaemonOwnership";
    private static final String FORMAT = "droidvm-daemon-owner-v1";

    private DaemonOwnership() {
    }

    public static final class Owner {
        private final String applicationId;
        private final int pid;
        private final long startTicks;
        private final String apkPath;

        private Owner(String applicationId, int pid, long startTicks, String apkPath) {
            if (applicationId == null
                || !applicationId.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
                throw new IllegalArgumentException("Invalid owner application ID");
            if (pid <= 1 || startTicks <= 0)
                throw new IllegalArgumentException("Invalid owner process identity");
            requireApkPath(apkPath);
            this.applicationId = applicationId;
            this.pid = pid;
            this.startTicks = startTicks;
            this.apkPath = apkPath;
        }

        String encode() {
            return FORMAT + "\n" + applicationId + "\n" + pid + "\n" + startTicks
                + "\n" + apkPath + "\n";
        }

        boolean sameProcess(Owner other) {
            return other != null && applicationId.equals(other.applicationId)
                && pid == other.pid && startTicks == other.startTicks && apkPath.equals(other.apkPath);
        }
    }

    interface ProcessProbe {
        String stat(int pid) throws Exception;
        String classpath(int pid) throws Exception;
    }

    interface SignalSender {
        boolean send(int pid, int signal);
    }

    private static final ProcessProbe LIVE_PROCESS = new ProcessProbe() {
        @Override
        public String stat(int pid) {
            return FileUtils.shellReadFile("/proc/" + pid + "/stat");
        }

        @Override
        public String classpath(int pid) {
            // Project only the identity field before output crosses the root-shell boundary.
            // Do not capture or persist the rest of the process's ambient environment.
            var result = RunUtils.runQuiet("tr '\\000' '\\n' < /proc/" + pid
                + "/environ | sed -n 's/^CLASSPATH=//p'");
            if (!result.isSuccess())
                throw new IllegalStateException("Cannot read daemon CLASSPATH");
            return parseClasspath(String.join("\n", result.getOut()));
        }
    };

    private static Path ownerFile() {
        return Paths.get(pathJoin(DATA_DIR, "run", "droidvmd.owner"));
    }

    /** Called only by the daemon while it holds its application's single-instance lock. */
    public static Owner publishCurrent() throws IOException {
        try {
            int pid = Process.myPid();
            var owner = new Owner(APPLICATION_ID, pid,
                parseStartTicks(FileUtils.readFile("/proc/self/stat"), pid),
                System.getenv("CLASSPATH"));
            writeAtomic(ownerFile(), owner);
            return owner;
        } catch (IllegalArgumentException e) {
            throw new IOException("Cannot establish the daemon's process identity", e);
        }
    }

    static void writeAtomic(Path file, Owner owner) throws IOException {
        var temporary = Files.createTempFile(file.getParent(), "droidvmd-owner-", ".tmp");
        try {
            Files.write(temporary, owner.encode().getBytes(StandardCharsets.UTF_8));
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    static Owner parse(String text) {
        if (text == null) throw new IllegalArgumentException("Missing daemon owner");
        var fields = text.split("\n", -1);
        // Shell transports return complete lines without the file's final LF.
        // Accept both representations without trimming identity fields.
        if ((fields.length != 5 && (fields.length != 6 || !fields[5].isEmpty()))
            || !FORMAT.equals(fields[0]))
            throw new IllegalArgumentException("Malformed daemon owner");
        return new Owner(fields[1], Integer.parseInt(fields[2]), Long.parseLong(fields[3]), fields[4]);
    }

    static Owner parseResult(RunResult result) {
        if (!result.isSuccess()) throw new IllegalStateException("Cannot read daemon owner");
        return parse(String.join("\n", result.getOut()));
    }

    static long parseStartTicks(String stat, int expectedPid) {
        if (stat == null) throw new IllegalArgumentException("Missing process stat");
        int open = stat.indexOf('(');
        int close = stat.lastIndexOf(')');
        if (open <= 0 || close <= open
            || Integer.parseInt(stat.substring(0, open).trim()) != expectedPid)
            throw new IllegalArgumentException("Unexpected process stat identity");
        // comm is parenthesized and can itself contain spaces and parentheses.
        // Starting at state (field 3), starttime (field 22) has index 19.
        var fields = stat.substring(close + 1).trim().split("\\s+");
        if (fields.length < 20 || fields[0].length() != 1)
            throw new IllegalArgumentException("Incomplete process stat");
        long ticks = Long.parseLong(fields[19]);
        if (ticks <= 0) throw new IllegalArgumentException("Invalid process start time");
        return ticks;
    }

    static String parseClasspath(String output) {
        if (output == null) throw new IllegalArgumentException("Missing daemon CLASSPATH");
        var path = output.endsWith("\n") ? output.substring(0, output.length() - 1) : output;
        requireApkPath(path);
        return path;
    }

    private static void requireApkPath(String path) {
        if (path == null || !path.startsWith("/") || !path.endsWith(".apk")
            || path.indexOf('\n') >= 0 || path.indexOf('\r') >= 0 || path.indexOf('\0') >= 0
            || path.indexOf(':') >= 0)
            throw new IllegalArgumentException("An absolute single APK CLASSPATH is required");
    }

    static boolean matchesLive(Owner owner, String applicationId, int pid, ProcessProbe probe) {
        if (owner == null || pid <= 1 || owner.pid != pid
            || !owner.applicationId.equals(applicationId)) return false;
        try {
            long before = parseStartTicks(probe.stat(pid), pid);
            var apkPath = probe.classpath(pid);
            long after = parseStartTicks(probe.stat(pid), pid);
            return before == owner.startTicks && after == before && owner.apkPath.equals(apkPath);
        } catch (Exception e) {
            return false;
        }
    }

    private static Owner readOwner() {
        return parseResult(RunUtils.runListQuiet("cat", ownerFile().toString()));
    }

    public static boolean owns(int pid) {
        try {
            return matchesLive(readOwner(), APPLICATION_ID, pid, LIVE_PROCESS);
        } catch (Exception e) {
            return false;
        }
    }

    /** Revalidate immediately before each signal, including escalation after a wait. */
    public static boolean signalIfOwned(int pid, int signal) {
        try {
            if (signalVerified(readOwner(), APPLICATION_ID, pid, signal, LIVE_PROCESS,
                ProcessUtils::shellKillProcess)) return true;
        } catch (Exception ignored) {
        }
        Log.w(TAG, "Daemon signal was not sent: ownership is unknown, changed, or signal failed");
        return false;
    }

    static boolean signalVerified(Owner owner, String applicationId, int pid, int signal,
                                  ProcessProbe probe, SignalSender sender) {
        return matchesLive(owner, applicationId, pid, probe) && sender.send(pid, signal);
    }

    /** Remove only the exact record published by this still-locked daemon. */
    public static boolean removeIfOwned(Owner current) {
        try {
            return removeIfOwned(ownerFile(), current);
        } catch (Exception e) {
            Log.w(TAG, "Daemon owner record cleanup failed", e);
            return false;
        }
    }

    static boolean removeIfOwned(Path file, Owner current) throws IOException {
        if (current == null || !Files.exists(file)) return false;
        final Owner published;
        try {
            published = parse(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return false;
        }
        return current.sameProcess(published) && Files.deleteIfExists(file);
    }
}
