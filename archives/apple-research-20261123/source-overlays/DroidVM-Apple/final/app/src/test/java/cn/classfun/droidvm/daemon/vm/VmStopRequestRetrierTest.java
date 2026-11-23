// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm;

import static org.junit.Assert.*;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public final class VmStopRequestRetrierTest {
    @Test public void observedExitDoesNotSendAnotherCommand() {
        new VmStopRequestRetrier(() -> true,
            () -> { fail("An exited run must not receive another stop request"); return false; },
            () -> fail("An exited run must not wait for a retry")).run();
    }

    @Test public void delayedSocketRetriesUntilRequestIsAccepted() {
        var attempts = new AtomicInteger();
        var pauses = new AtomicInteger();
        var exited = new AtomicBoolean();
        new VmStopRequestRetrier(exited::get, () -> attempts.incrementAndGet() == 3,
            () -> pauses.incrementAndGet()).run();
        assertEquals(3, attempts.get());
        assertEquals(2, pauses.get());
        assertFalse("Request acceptance is not a process-exit acknowledgement", exited.get());
    }

    @Test public void controlExceptionKeepsTheRunOwnedAndRetries() {
        var attempts = new AtomicInteger();
        var pauses = new AtomicInteger();
        new VmStopRequestRetrier(() -> false, () -> {
            if (attempts.incrementAndGet() == 1) throw new IllegalStateException("Socket is not ready");
            return true;
        }, () -> pauses.incrementAndGet()).run();
        assertEquals(2, attempts.get());
        assertEquals(1, pauses.get());
    }

    @Test public void rejectedRequestsEndOnlyWhenExitIsObserved() {
        var exited = new AtomicBoolean();
        var attempts = new AtomicInteger();
        var pauses = new AtomicInteger();
        new VmStopRequestRetrier(exited::get,
            () -> { attempts.incrementAndGet(); return false; },
            () -> { if (pauses.incrementAndGet() == 4) exited.set(true); }).run();
        assertEquals(4, attempts.get());
        assertEquals(4, pauses.get());
        assertTrue(exited.get());
    }

    @Test public void interruptionCannotSkipRetryAndIsRestored() {
        Thread.interrupted();
        var attempts = new AtomicInteger();
        var pauses = new AtomicInteger();
        try {
            new VmStopRequestRetrier(() -> false, () -> attempts.incrementAndGet() == 3,
                () -> { if (pauses.incrementAndGet() == 1) throw new InterruptedException(); }).run();
            assertEquals(3, attempts.get());
            assertEquals(2, pauses.get());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test public void longDelayDoesNotConvertRejectionToCompletion() {
        var exited = new AtomicBoolean();
        var attempts = new AtomicInteger();
        new VmStopRequestRetrier(exited::get,
            () -> { attempts.incrementAndGet(); return false; },
            () -> { if (attempts.get() == 100) exited.set(true); }).run();
        assertEquals("There is no deadline that releases a live memory owner", 100, attempts.get());
        assertTrue(exited.get());
    }
}
