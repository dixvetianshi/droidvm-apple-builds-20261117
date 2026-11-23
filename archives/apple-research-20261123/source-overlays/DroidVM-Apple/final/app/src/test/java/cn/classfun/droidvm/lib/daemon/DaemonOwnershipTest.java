package cn.classfun.droidvm.lib.daemon;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import cn.classfun.droidvm.lib.run.RunResult;
import cn.classfun.droidvm.lib.utils.RunUtils;

public class DaemonOwnershipTest {
    private static final String APPLE = "cn.classfun.droidvm.apple";
    private static final String ORIGINAL = "cn.classfun.droidvm";
    private static final String APK = "/data/app/droidvm apple/base.apk";
    private static final int PID = 11568;
    private static final long START = 7654321L;

    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    private static String record(String application, long start) {
        return "droidvm-daemon-owner-v1\n" + application + "\n" + PID + "\n" + start
            + "\n" + APK + "\n";
    }

    private static String stat(long start) {
        // state is field 3; the next 18 values are fields 4 through 21.
        var fields = new String[20];
        Arrays.fill(fields, "0");
        fields[0] = "S";
        fields[19] = String.valueOf(start);
        return PID + " (droidvmd (comm) with spaces)) " + String.join(" ", fields);
    }

    private static DaemonOwnership.ProcessProbe probe(long start, String apkPath) {
        return new DaemonOwnership.ProcessProbe() {
            @Override
            public String stat(int pid) {
                return DaemonOwnershipTest.stat(start);
            }

            @Override
            public String classpath(int pid) {
                return apkPath;
            }
        };
    }

    private static RunResult result(int code, Iterable<String> lines) {
        return new RunResult() {
            @Override
            public int getCode() { return code; }

            @Override
            public Iterable<String> getOut() { return lines; }

            @Override
            public Iterable<String> getErr() { return Arrays.asList(); }
        };
    }

    private static void assertMalformed(String text) {
        try {
            DaemonOwnership.parse(text);
            fail("Malformed record must not establish ownership");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void recordPreservesOnlyAppAndProcessIdentityIncludingActualApkPath() {
        var text = record(APPLE, START);
        var owner = DaemonOwnership.parse(text);
        assertEquals(text, owner.encode());
        assertTrue(DaemonOwnership.matchesLive(owner, APPLE, PID, probe(START, APK)));
        assertFalse(DaemonOwnership.matchesLive(owner, APPLE, PID,
            probe(START, "/data/app/updated-droidvm/base.apk")));
        assertFalse(DaemonOwnership.matchesLive(owner, APPLE, PID + 1, probe(START, APK)));
    }

    @Test
    public void rootAndProcessShellLineTransportsRetainTheSameOwnerWithoutFinalLf() {
        var text = record(APPLE, START);
        var processLines = RunUtils.outStringToList(text);
        var rootLines = Arrays.asList("droidvm-daemon-owner-v1", APPLE, String.valueOf(PID),
            String.valueOf(START), APK);
        assertEquals(text, DaemonOwnership.parseResult(result(0, processLines)).encode());
        assertEquals(text, DaemonOwnership.parseResult(result(0, rootLines)).encode());
        assertEquals(text, DaemonOwnership.parse(text.substring(0, text.length() - 1)).encode());
        try {
            DaemonOwnership.parseResult(result(1, rootLines));
            fail("Failed shell result must not establish ownership from partial output");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void wrongVariantCannotSignalEvenWithTheSamePidStartAndClasspath() {
        var sent = new AtomicInteger();
        var owner = DaemonOwnership.parse(record(ORIGINAL, START));
        assertFalse(DaemonOwnership.signalVerified(owner, APPLE, PID, 2, probe(START, APK),
            (pid, signal) -> { sent.incrementAndGet(); return true; }));
        assertEquals(0, sent.get());
    }

    @Test
    public void escalationRevalidatesTheStartTimeAndRefusesAReusedPid() {
        var sent = new AtomicInteger();
        var owner = DaemonOwnership.parse(record(APPLE, START));
        DaemonOwnership.SignalSender sender = (pid, signal) -> {
            assertEquals(PID, pid);
            sent.incrementAndGet();
            return true;
        };
        assertTrue(DaemonOwnership.signalVerified(owner, APPLE, PID, 2, probe(START, APK), sender));
        assertFalse(DaemonOwnership.signalVerified(owner, APPLE, PID, 9,
            probe(START + 1, APK), sender));
        assertEquals(1, sent.get());
    }

    @Test
    public void processIdentityChangingDuringTheProbeOrUnavailableCannotSignal() {
        var owner = DaemonOwnership.parse(record(APPLE, START));
        var reads = new AtomicInteger();
        var changing = new DaemonOwnership.ProcessProbe() {
            @Override
            public String stat(int pid) {
                return DaemonOwnershipTest.stat(reads.incrementAndGet() == 1 ? START : START + 1);
            }

            @Override
            public String classpath(int pid) {
                return APK;
            }
        };
        assertFalse(DaemonOwnership.signalVerified(owner, APPLE, PID, 2, changing,
            (pid, signal) -> { fail("Changed identity must not signal"); return true; }));
        assertFalse(DaemonOwnership.matchesLive(owner, APPLE, PID, new DaemonOwnership.ProcessProbe() {
            @Override
            public String stat(int pid) throws Exception {
                throw new Exception("Process disappeared or access denied");
            }

            @Override
            public String classpath(int pid) {
                return APK;
            }
        }));
        assertFalse(DaemonOwnership.matchesLive(null, APPLE, PID, probe(START, APK)));
    }

    @Test
    public void malformedOwnershipNeverFallsBackToThePidOrProcessName() {
        var valid = record(APPLE, START);
        assertMalformed(null);
        assertMalformed(valid.replace("-v1", "-v2"));
        assertMalformed(valid.substring(0, valid.length() - 2));
        assertMalformed(valid + "droidvmd\n");
        assertMalformed(valid.replace(APPLE, "wrong variant"));
        assertMalformed(valid.replace("\n" + PID + "\n", "\n1\n"));
        assertMalformed(valid.replace("\n" + START + "\n", "\n0\n"));
        assertMalformed(valid.replace("\n" + START + "\n", "\nunknown\n"));
        assertMalformed(valid.replace(APK, "base.apk"));
        assertMalformed(valid.replace(APK, APK + ":/data/app/another/base.apk"));
        assertMalformed(valid.replace(APK, APK + "\r"));
    }

    @Test
    public void statParserUsesTheLastCommParenthesisAndRejectsWrongPidOrMissingStart() {
        assertEquals(START, DaemonOwnership.parseStartTicks(stat(START), PID));
        for (var malformed : new String[]{PID + " (droidvmd) S 1 2", stat(0),
            stat(START).replace(String.valueOf(PID), String.valueOf(PID + 1))}) {
            try {
                DaemonOwnership.parseStartTicks(malformed, PID);
                fail("Invalid stat must not establish process identity");
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    @Test
    public void selectedClasspathRequiresOneCompleteApkPath() {
        assertEquals(APK, DaemonOwnership.parseClasspath(APK + "\n"));
        assertEquals(APK, DaemonOwnership.parseClasspath(APK));
        for (var malformed : new String[]{"", "base.apk", APK + "\n" + APK + "\n",
            APK + ":/data/app/another/base.apk", APK + "\0"}) {
            try {
                DaemonOwnership.parseClasspath(malformed);
                fail("Missing or ambiguous CLASSPATH must not establish ownership");
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    @Test
    public void owningCleanupRetainsForeignReusedAndMalformedRecords() throws Exception {
        Path file = temporary.newFile("droidvmd.owner").toPath();
        var current = DaemonOwnership.parse(record(APPLE, START));
        for (var preserved : new String[]{record(ORIGINAL, START), record(APPLE, START + 1),
            "malformed\n", record(APPLE, START).replace(APK, "/data/app/other/base.apk")}) {
            Files.write(file, preserved.getBytes(StandardCharsets.UTF_8));
            assertFalse(DaemonOwnership.removeIfOwned(file, current));
            assertEquals(preserved, new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
        }
        Files.write(file, current.encode().getBytes(StandardCharsets.UTF_8));
        assertFalse(DaemonOwnership.removeIfOwned(file, null));
        assertTrue(Files.exists(file));
        assertTrue(DaemonOwnership.removeIfOwned(file, current));
        assertFalse(Files.exists(file));
        assertFalse(DaemonOwnership.removeIfOwned(file, current));
    }

    @Test
    public void publicationReplacesAStaleRecordAndLeavesNoTemporaryOwnerFiles() throws Exception {
        Path directory = temporary.newFolder("run").toPath();
        Path file = directory.resolve("droidvmd.owner");
        Files.write(file, record(APPLE, START - 1).getBytes(StandardCharsets.UTF_8));
        var current = DaemonOwnership.parse(record(APPLE, START));
        DaemonOwnership.writeAtomic(file, current);
        assertEquals(current.encode(), new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
        try (var files = Files.list(directory)) {
            assertEquals(1L, files.count());
        }
    }
}
