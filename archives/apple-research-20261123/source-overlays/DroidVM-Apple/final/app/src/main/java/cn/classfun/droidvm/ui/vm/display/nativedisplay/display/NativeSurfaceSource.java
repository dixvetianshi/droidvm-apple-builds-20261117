// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.ui.vm.display.nativedisplay.display;

import android.os.Handler;
import android.os.IBinder;
import android.view.SurfaceView;

import androidx.annotation.NonNull;

import java.util.function.Supplier;

import cn.classfun.droidvm.ui.vm.display.base.DisplaySource;

/**
 * {@link DisplaySource} for the native display path: crosvm renders straight into the
 * SurfaceView's Surface via the per-VM ICrosvmAndroidDisplayService. Wraps {@link DisplayProvider}
 * behind the pluggable source interface, so a future source (e.g. zero-copy AHardwareBuffer)
 * slots into the same console. The provider attaches each new Surface when the binder resolves
 * and asks the native service to replay its last frame, so {@link #start()} is a no-op. The replay
 * is best-effort; connection state does not report first-frame presentation. No guest-resize
 * channel on this path yet.
 */
public final class NativeSurfaceSource implements DisplaySource {
    private final DisplayProvider provider;
    private boolean closed;

    /**
     * @param displayBinderSupplier resolves the per-VM display binder (blocking, called off the
     *                              main thread); null while the daemon broker isn't attached yet.
     */
    public NativeSurfaceSource(@NonNull SurfaceView surfaceView, int guestWidth, int guestHeight,
                               @NonNull Supplier<IBinder> displayBinderSupplier,
                               @NonNull Handler mainHandler, @NonNull Callbacks callbacks) {
        provider = new DisplayProvider(surfaceView, guestWidth, guestHeight, displayBinderSupplier,
            connected -> {
                if (!closed) callbacks.onStateChanged(connected ? State.CONNECTED : State.CONNECTING);
            },
            config -> {
                if (!closed) callbacks.onContentSize(config.width, config.height);
            });
    }

    /**
     * Follow the guest cursor. Positions are GUEST framebuffer coordinates, delivered on the main
     * thread, and arrive only on this display path -- the VNC path has no such channel.
     *
     * The caller decides what to do with them, and in particular whether to act at all: a cursor
     * move caused by a remote desktop session is indistinguishable here from one the user made,
     * so gating on "the user is currently driving the pointer" belongs to the consumer.
     */
    @Override
    public void setCursorView(android.view.SurfaceView cursorView) {
        provider.setCursorView(cursorView);
    }

    @Override
    public void setCursorListener(java.util.function.BiConsumer<Integer, Integer> listener) {
        provider.setCursorListener(listener == null ? null : listener::accept);
    }

    @Override
    public void start() {
    }

    @Override
    public void shutdown() {
        closed = true;
        provider.shutdown();
    }

    @Override
    public void setActive(boolean active) {
        if (!closed) provider.setActive(active);
    }

    @Override
    public boolean supportsGuestResize() {
        return false;
    }

    @Override
    public void requestGuestResize(int width, int height) {
    }
}
