// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.ui.vm.display.nativedisplay.display;

import static cn.classfun.droidvm.lib.utils.StringUtils.fmt;

import android.crosvm.DisplayConfig;
import android.crosvm.ICrosvmAndroidDisplayService;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import androidx.annotation.NonNull;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** One resumed console's binding to a per-VM/per-screen native display service. */
final class DisplayProvider {
    private static final String TAG = "NativeDisplayProvider";
    private static final long BINDER_RETRY_MIN_MS = 1000;
    private static final long BINDER_RETRY_MAX_MS = 5000;
    private static final long CONFIG_POLL_MS = 1000;
    static final int CURSOR_PLANE_PX = 64;

    private final SurfaceView mainView;
    private int width;
    private int height;
    private final Supplier<IBinder> binderProvider;
    private final Consumer<Boolean> onConnected;
    private final Consumer<DisplayConfig> onDisplayConfig;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor =
        Executors.newSingleThreadExecutor(r -> new Thread(r, "NativeDisplayProvider-bg"));
    private final AtomicBoolean fetching = new AtomicBoolean();
    private final DisplayConnectionEpoch epoch = new DisplayConnectionEpoch();

    // Main-thread fields. Positive tokens are scoped to displayService and the plane.
    // Surface recreation updates that token; only a new foreground activation may use zero.
    private ICrosvmAndroidDisplayService displayService;
    private IBinder.DeathRecipient deathRecipient;
    private long mainSession;
    private long cursorSession;
    private boolean mainClaimAttempted;
    private boolean cursorClaimAttempted;
    private boolean needsSend;
    private boolean cursorSurfaceSent;
    private boolean needsRecreate;
    private CursorPositionStream cursorStream;
    private CursorPositionStream.Listener cursorListener;
    private SurfaceView cursorView;
    private SurfaceHolder.Callback cursorCallback;
    private final SurfaceHolder.Callback mainCallback = new Callback();

    DisplayProvider(@NonNull SurfaceView mainView, int width, int height,
                    @NonNull Supplier<IBinder> binderProvider,
                    @NonNull Consumer<Boolean> onConnected,
                    @NonNull Consumer<DisplayConfig> onDisplayConfig) {
        this.mainView = mainView;
        this.width = width;
        this.height = height;
        this.binderProvider = binderProvider;
        this.onConnected = onConnected;
        this.onDisplayConfig = onDisplayConfig;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            mainView.setSurfaceLifecycle(SurfaceView.SURFACE_LIFECYCLE_FOLLOWS_ATTACHMENT);
        mainView.getHolder().addCallback(mainCallback);
        mainView.getHolder().setFixedSize(width, height);
        needsSend = valid(mainView.getHolder());
    }

    void setActive(boolean active) {
        if (!epoch.setActive(active)) return;
        if (!active) {
            detachBindings();
            return;
        }
        // A service death leaves an abandoned BufferQueue. Recreate only when this
        // console becomes active, and never hand the dead producer's queue to a new VMM.
        if (needsRecreate) {
            needsRecreate = false;
            recreateSurface(mainView);
            if (cursorView != null) recreateSurface(cursorView);
        }
        needsSend = valid(mainView.getHolder());
        cursorSurfaceSent = false;
        if (displayService == null) fetchBinder();
        else {
            applyPendingSurface();
            if (cursorView != null) trySendCursorSurface(cursorView.getHolder());
            attachCursorStream();
            startConfigPoll(displayService, epoch.snapshot());
        }
    }

    private static boolean valid(SurfaceHolder holder) {
        Surface surface = holder.getSurface();
        return surface != null && surface.isValid();
    }

    private void recreateSurface(SurfaceView view) {
        if (!(view.getParent() instanceof android.view.ViewGroup)) return;
        var group = (android.view.ViewGroup) view.getParent();
        int index = group.indexOfChild(view);
        var layout = view.getLayoutParams();
        group.removeView(view);
        group.addView(view, index, layout);
    }

    private void fetchBinder() {
        if (!epoch.isActive() || executor.isShutdown() || !fetching.compareAndSet(false, true)) return;
        final long requestedEpoch = epoch.snapshot();
        try {
            executor.submit(() -> {
                try {
                    long backoff = BINDER_RETRY_MIN_MS;
                    while (!Thread.currentThread().isInterrupted() && epoch.isCurrent(requestedEpoch)) {
                        IBinder binder = null;
                        try { binder = binderProvider.get(); }
                        catch (Exception e) { Log.w(TAG, "Display binder lookup failed", e); }
                        if (binder != null) {
                            final IBinder got = binder;
                            mainHandler.post(() -> onBinderReady(got, requestedEpoch));
                            return;
                        }
                        try { Thread.sleep(backoff); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                        backoff = Math.min(backoff * 2, BINDER_RETRY_MAX_MS);
                    }
                } finally {
                    fetching.set(false);
                    mainHandler.post(() -> {
                        if (epoch.isActive() && displayService == null) fetchBinder();
                    });
                }
            });
        } catch (RejectedExecutionException e) {
            fetching.set(false);
        }
    }

    private void onBinderReady(IBinder binder, long requestedEpoch) {
        if (!epoch.isCurrent(requestedEpoch) || displayService != null) return;
        var service = ICrosvmAndroidDisplayService.Stub.asInterface(binder);
        IBinder.DeathRecipient recipient = () -> mainHandler.post(() -> onBinderDeath(binder));
        try { binder.linkToDeath(recipient, 0); }
        catch (RemoteException e) { return; }
        displayService = service;
        deathRecipient = recipient;
        try {
            var config = service.getDisplayConfig();
            applyConfigIfChanged(service, requestedEpoch, config);
        } catch (Exception e) {
            Log.w(TAG, fmt("getDisplayConfig unavailable; using %dx%d", width, height));
        }
        onConnected.accept(true); // Binder connection; this does not certify frame presentation.
        applyPendingSurface();
        if (cursorView != null) trySendCursorSurface(cursorView.getHolder());
        attachCursorStream();
        startConfigPoll(service, requestedEpoch);
    }

    private void onBinderDeath(IBinder binder) {
        if (epoch.isClosed() || displayService == null || displayService.asBinder() != binder) return;
        epoch.rebind();
        displayService = null;
        deathRecipient = null;
        mainSession = cursorSession = 0;
        mainClaimAttempted = cursorClaimAttempted = false;
        needsSend = false;
        cursorSurfaceSent = false;
        closeCursorStream(null);
        needsRecreate = true;
        if (epoch.isActive()) {
            onConnected.accept(false);
            needsRecreate = false;
            recreateSurface(mainView);
            if (cursorView != null) recreateSurface(cursorView);
            fetchBinder();
        }
    }

    private void startConfigPoll(ICrosvmAndroidDisplayService service, long requestedEpoch) {
        if (!epoch.isCurrent(requestedEpoch) || executor.isShutdown()) return;
        try {
            executor.submit(() -> {
                while (!Thread.currentThread().isInterrupted() && epoch.isCurrent(requestedEpoch)) {
                    try { Thread.sleep(CONFIG_POLL_MS); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    if (!epoch.isCurrent(requestedEpoch)) return;
                    DisplayConfig config;
                    try { config = service.getDisplayConfig(); }
                    catch (Exception e) { return; }
                    mainHandler.post(() -> applyConfigIfChanged(service, requestedEpoch, config));
                }
            });
        } catch (RejectedExecutionException ignored) {
        }
    }

    private void applyConfigIfChanged(ICrosvmAndroidDisplayService service, long requestedEpoch,
                                      DisplayConfig config) {
        if (!epoch.isCurrent(requestedEpoch) || displayService != service || config == null
            || config.width <= 0 || config.height <= 0) return;
        if (config.width == width && config.height == height) return;
        width = config.width;
        height = config.height;
        mainView.getHolder().setFixedSize(width, height);
        onDisplayConfig.accept(config);
    }

    private void applyPendingSurface() {
        if (epoch.isActive() && displayService != null && needsSend)
            trySendSurface(mainView.getHolder());
    }

    private void trySendSurface(SurfaceHolder holder) {
        var service = displayService;
        if (!epoch.isActive() || service == null || !needsSend || !valid(holder)) return;
        if (mainSession == 0 && mainClaimAttempted) return;
        try {
            if (mainSession == 0) mainClaimAttempted = true;
            long accepted = service.setSurfaceForSession(holder.getSurface(), mainSession, false);
            needsSend = false;
            if (accepted <= 0) {
                // Preserve the old token. A stale callback is never upgraded to a fresh claim.
                onConnected.accept(false);
                return;
            }
            mainSession = accepted;
            service.drawSavedFrameForSession(mainSession, false);
            attachCursorStream();
        } catch (Exception e) {
            // Unlike the legacy inout Surface reply, this API must return an actual token.
            Log.w(TAG, "Owned main surface was not acknowledged", e);
        }
    }

    private void removePlane(ICrosvmAndroidDisplayService service, long session,
                             boolean cursor, boolean endSession) {
        if (service == null || session <= 0) return;
        try { service.removeSurfaceForSession(session, cursor, endSession); }
        catch (Exception e) { Log.w(TAG, "Owned surface detach failed", e); }
    }

    private final class Callback implements SurfaceHolder.Callback {
        @Override public void surfaceCreated(@NonNull SurfaceHolder holder) {
            if (epoch.isClosed()) return;
            holder.setFixedSize(width, height);
            needsSend = true;
        }
        @Override public void surfaceChanged(@NonNull SurfaceHolder holder, int f, int w, int h) {
            trySendSurface(holder);
        }
        @Override public void surfaceDestroyed(@NonNull SurfaceHolder holder) {
            if (epoch.isClosed()) return;
            needsSend = false;
            // Surface replacement keeps this binding identity. Pause/close explicitly end it.
            removePlane(displayService, mainSession, false, false);
        }
    }

    void setCursorListener(CursorPositionStream.Listener listener) {
        if (epoch.isClosed()) return;
        cursorListener = listener;
        if (listener == null) closeCursorStream(displayService);
        else attachCursorStream();
    }

    private void attachCursorStream() {
        if (!epoch.isActive() || mainSession <= 0 || cursorListener == null
            || displayService == null || cursorStream != null) return;
        cursorStream = CursorPositionStream.attach(displayService, mainSession, cursorListener);
    }

    private void closeCursorStream(ICrosvmAndroidDisplayService service) {
        if (service != null && mainSession > 0) {
            try { service.clearCursorStreamForSession(mainSession); }
            catch (Exception e) { Log.w(TAG, "Owned cursor stream detach failed", e); }
        }
        if (cursorStream != null) {
            cursorStream.close();
            cursorStream = null;
        }
    }

    void setCursorView(SurfaceView view) {
        if (epoch.isClosed() || cursorView == view) return;
        if (cursorView != null) {
            if (cursorCallback != null) cursorView.getHolder().removeCallback(cursorCallback);
            removePlane(displayService, cursorSession, true, true);
            cursorSession = 0;
            cursorClaimAttempted = false;
            cursorSurfaceSent = false;
        }
        cursorView = view;
        if (view == null) return;
        view.setZOrderMediaOverlay(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            view.setSurfaceLifecycle(SurfaceView.SURFACE_LIFECYCLE_FOLLOWS_ATTACHMENT);
        view.getHolder().setFixedSize(CURSOR_PLANE_PX, CURSOR_PLANE_PX);
        final SurfaceView registeredView = view;
        cursorCallback = new SurfaceHolder.Callback() {
            private boolean current() { return !epoch.isClosed() && cursorView == registeredView; }
            @Override public void surfaceCreated(@NonNull SurfaceHolder holder) {
                if (!current()) return;
                cursorSurfaceSent = false;
                trySendCursorSurface(holder);
            }
            @Override public void surfaceChanged(@NonNull SurfaceHolder holder, int f, int w, int h) {
                if (current()) trySendCursorSurface(holder);
            }
            @Override public void surfaceDestroyed(@NonNull SurfaceHolder holder) {
                if (!current()) return;
                cursorSurfaceSent = false;
                removePlane(displayService, cursorSession, true, false);
            }
        };
        view.getHolder().addCallback(cursorCallback);
        trySendCursorSurface(view.getHolder());
    }

    private void trySendCursorSurface(SurfaceHolder holder) {
        var service = displayService;
        if (!epoch.isActive() || service == null || cursorSurfaceSent || !valid(holder)) return;
        if (cursorSession == 0 && cursorClaimAttempted) return;
        try {
            if (cursorSession == 0) cursorClaimAttempted = true;
            long accepted = service.setSurfaceForSession(holder.getSurface(), cursorSession, true);
            cursorSurfaceSent = true;
            if (accepted <= 0) return; // Do not reacquire after a stale update.
            cursorSession = accepted;
            service.drawSavedFrameForSession(cursorSession, true);
        } catch (Exception e) { Log.w(TAG, "Owned cursor surface was not acknowledged", e); }
    }

    private void detachBindings() {
        var service = displayService;
        closeCursorStream(service);
        removePlane(service, mainSession, false, true);
        removePlane(service, cursorSession, true, true);
        mainSession = cursorSession = 0;
        mainClaimAttempted = cursorClaimAttempted = false;
        needsSend = false;
        cursorSurfaceSent = false;
    }

    void shutdown() {
        if (epoch.isClosed()) return;
        epoch.close();
        detachBindings();
        if (displayService != null && deathRecipient != null) {
            try { displayService.asBinder().unlinkToDeath(deathRecipient, 0); }
            catch (Exception ignored) {}
        }
        mainView.getHolder().removeCallback(mainCallback);
        if (cursorView != null && cursorCallback != null)
            cursorView.getHolder().removeCallback(cursorCallback);
        executor.shutdownNow();
        mainHandler.removeCallbacksAndMessages(null);
        displayService = null;
        deathRecipient = null;
    }
}
