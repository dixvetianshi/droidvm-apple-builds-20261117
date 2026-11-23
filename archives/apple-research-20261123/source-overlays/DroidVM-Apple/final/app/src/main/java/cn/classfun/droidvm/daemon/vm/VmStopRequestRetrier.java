// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.daemon.vm;

import java.util.Objects;
import java.util.function.BooleanSupplier;

/** Retries a stop request; process exit remains the VM worker's completion signal. */
final class VmStopRequestRetrier implements Runnable {
    interface Pause {
        void awaitRetry() throws InterruptedException;
    }

    private final BooleanSupplier exitObserved;
    private final BooleanSupplier requestStop;
    private final Pause pause;

    VmStopRequestRetrier(BooleanSupplier exitObserved, BooleanSupplier requestStop, Pause pause) {
        this.exitObserved = Objects.requireNonNull(exitObserved);
        this.requestStop = Objects.requireNonNull(requestStop);
        this.pause = Objects.requireNonNull(pause);
    }

    @Override public void run() {
        boolean interrupted = false;
        try {
            while (!exitObserved.getAsBoolean()) {
                try {
                    if (requestStop.getAsBoolean()) return;
                } catch (RuntimeException ignored) {
                    // A temporarily unavailable control socket cannot authorize process death.
                }
                try {
                    pause.awaitRetry();
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
}
