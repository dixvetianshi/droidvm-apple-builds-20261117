// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.ui.vm.display.nativedisplay.display;

import static org.junit.Assert.*;
import org.junit.Test;

public final class DisplayConnectionEpochTest {
    @Test public void pauseAndResumeRejectWorkFromThePreviousForegroundBinding() {
        var state = new DisplayConnectionEpoch();
        assertTrue(state.setActive(true));
        long first = state.snapshot();
        assertTrue(state.isCurrent(first));
        assertTrue(state.setActive(false));
        assertFalse(state.isCurrent(first));
        assertTrue(state.setActive(true));
        assertFalse(state.isCurrent(first));
        assertTrue(state.isCurrent(state.snapshot()));
    }

    @Test public void serviceReplacementRejectsOldBinderAndConfigWork() {
        var state = new DisplayConnectionEpoch();
        state.setActive(true);
        long oldBinder = state.snapshot();
        state.rebind();
        assertFalse(state.isCurrent(oldBinder));
        assertTrue(state.isCurrent(state.snapshot()));
    }

    @Test public void closedProviderCannotBeReactivatedByALateReadyCallback() {
        var state = new DisplayConnectionEpoch();
        state.setActive(true);
        long waiting = state.snapshot();
        state.close();
        assertFalse(state.isCurrent(waiting));
        assertFalse(state.setActive(true));
        assertFalse(state.isActive());
        assertTrue(state.isClosed());
    }

    @Test public void duplicateActivationDoesNotCreateAnotherBindingEpoch() {
        var state = new DisplayConnectionEpoch();
        state.setActive(true);
        long current = state.snapshot();
        assertFalse(state.setActive(true));
        assertEquals(current, state.snapshot());
        assertTrue(state.isCurrent(current));
    }
}
