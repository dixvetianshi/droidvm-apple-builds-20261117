// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.ui.vm.display.nativedisplay.display;

import java.util.concurrent.atomic.AtomicLong;

/** Rejects work queued by an earlier foreground/binder connection. */
final class DisplayConnectionEpoch {
    private final AtomicLong epoch = new AtomicLong();
    private volatile boolean active;
    private volatile boolean closed;

    boolean setActive(boolean value) {
        if (closed || active == value) return false;
        active = value;
        epoch.incrementAndGet();
        return true;
    }

    void rebind() { epoch.incrementAndGet(); }
    long snapshot() { return epoch.get(); }
    boolean isCurrent(long expected) { return isActive() && epoch.get() == expected; }
    boolean isActive() { return active && !closed; }
    boolean isClosed() { return closed; }

    void close() {
        closed = true;
        active = false;
        epoch.incrementAndGet();
    }
}
