// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm;

import static java.util.Objects.requireNonNull;
import static cn.classfun.droidvm.lib.store.enums.Enums.optEnum;
import static cn.classfun.droidvm.lib.utils.NetUtils.generateRandomAvailablePort;
import static cn.classfun.droidvm.lib.utils.ProcessUtils.shellKillProcess;
import static cn.classfun.droidvm.lib.utils.StringUtils.fmt;
import static cn.classfun.droidvm.lib.utils.StringUtils.generateRandomPassword;
import static cn.classfun.droidvm.lib.utils.StringUtils.urlEncodeBytesAll;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import cn.classfun.droidvm.daemon.console.ConsoleStream;
import cn.classfun.droidvm.daemon.vm.backend.BackendBase;
import cn.classfun.droidvm.daemon.vm.backend.CrosvmHostPolicy;
import cn.classfun.droidvm.lib.data.CrosvmExit;
import cn.classfun.droidvm.lib.hugepage.PoolPreflight;
import cn.classfun.droidvm.lib.natives.NativeProcess;
import cn.classfun.droidvm.lib.natives.UnixHelper;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.network.NetworkState;
import cn.classfun.droidvm.lib.store.vm.DisplayExporter;
import cn.classfun.droidvm.lib.store.vm.VMScreenConfig;
import cn.classfun.droidvm.lib.store.vm.VMBackend;
import cn.classfun.droidvm.lib.store.vm.VMConfig;
import cn.classfun.droidvm.lib.store.vm.VMNicConfig;
import cn.classfun.droidvm.lib.store.vm.VMState;
import cn.classfun.droidvm.lib.utils.JsonUtils;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

public final class VMInstance extends VMConfig {
    private static final String TAG = "VMInstance";
    /**
     * Read from every thread that asks what this VM is doing -- IPC handlers, the auto-start
     * sweep, stopAll, the worker itself -- and written by the worker and by start(). Volatile so
     * that a reader outside {@link #startLock} sees the current answer rather than a cached one.
     */
    private volatile VMState state = VMState.STOPPED;
    /** Serialises the run-up to STARTING against a second caller; see {@link #start}. */
    private final Object startLock = new Object();
    private volatile NativeProcess process;
    private volatile boolean stoppedByUser = false;
    private int exitCode = -1;
    private BackendBase backend;
    private VMBackendInstance backendInstance;
    private Thread workerThread;
    private volatile Thread stopRequestThread;
    private volatile NativeProcess stopRequestProcess;
    private final VMInstanceStore store;
    private BootPlan bootPlan;
    private String bootEntryOverride;
    private volatile String startError;
    private volatile boolean rebootRequested = false;
    /** Set while a start that failed on unpinnable memory is being tried a second time. */
    private volatile boolean pinRetryUsed = false;
    /** A run this long counts as "the VM started", re-arming the one-shot pin retry. */
    private static final long PIN_RETRY_RESET_MS = 60_000;

    // Delay before relaunching on reboot: lets the kernel settle same-name TAP
    // teardown/recreate and throttles a guest reboot-loop (no restart cap).
    private static final long REBOOT_RELAUNCH_DELAY_MS = 500;

    public interface VMEventCallback {
        @SuppressWarnings("unused")
        void onVMEvent(@NonNull String vmId, @NonNull String event, @NonNull JSONObject data);
    }

    public VMInstance(@NonNull VMInstanceStore store) {
        super();
        this.store = store;
    }

    public VMInstance(@NonNull VMInstanceStore store, @NonNull JSONObject obj) throws JSONException {
        super(obj);
        this.store = store;
        if (obj.has("state")) state = VMState.valueOf(obj.getString("state"));
    }

    @NonNull
    public BackendBase getBackend() {
        if (this.backend == null) {
            VMBackend backend = optEnum(this.item, "backend", VMBackend.DEFAULT);
            this.backend = BackendBase.find(backend.name().toLowerCase());
            if (this.backend == null) throw new RuntimeException(fmt(
                "Backend %s not found for VM %s",
                backend.name(), getName()
            ));
        }
        return this.backend;
    }

    @NonNull
    synchronized VMBackendInstance getBackendInstance() {
        if (this.backendInstance == null)
            this.backendInstance = getBackend().create(store.context, this);
        return this.backendInstance;
    }

    /**
     * Control socket of the running backend, or null when there is none. Reads the field rather
     * than {@link #getBackendInstance()} on purpose: asking for the path must never be what
     * creates a backend for a VM that is not running.
     */
    @Nullable
    public synchronized String getControlSocketPath() {
        return backendInstance == null ? null : backendInstance.getControlSocketPath();
    }

    /**
     * Forwards UI-sent evdev bytes to the running backend's native-display input channel for
     * [screenId] -- the screen the console that sent them is showing, which is what picks between
     * two screens' absolute devices.
     */
    public boolean writeNativeInput(@NonNull String screenId, int channel, @NonNull byte[] data) {
        // Only a running VM has a backend with bound input sockets; skip otherwise so a stale or
        // spoofed input call can't lazily create an idle backend instance.
        if (state != VMState.RUNNING) return false;
        return getBackendInstance().writeNativeInput(screenId, channel, data);
    }

    @NonNull
    public VMState getState() {
        return state;
    }

    public long getPid() {
        if (process != null) return process.pid();
        return -1;
    }

    private void setState(@NonNull VMState newState) {
        this.state = newState;
        Log.i(TAG, fmt("VM %s [%s] -> %s", getName(), getId().toString(), newState.name()));
        fireEvent("state", null);
        // The one place every transition passes through, so the foreground service a peripheral
        // may need is raised and dropped from the same edge the guest device appears on.
        PeripheralForegroundControl.refresh(store);
        // Same edge for the host USB devices this VM borrowed. Fully guarded: a state change is
        // never allowed to fail because of what the manager did with them.
        try {
            store.context.getUsb().onVmState(this, newState);
        } catch (Exception e) {
            Log.w(TAG, "usb: state hook failed", e);
        }
        // And the physical keyboard, if a console for this VM had it grabbed: a guest that is no
        // longer running has no keyboard socket to type into, so the keys go back to Android on
        // the same edge. Guarded for the same reason.
        try {
            store.context.getKeyboard().onVmState(this, newState);
        } catch (Exception e) {
            Log.w(TAG, "keyboard: state hook failed", e);
        }
    }

    private void fireEvent(@NonNull String event, @Nullable JSONObject extra) {
        var cb = store.context.vmEventCallback;
        if (cb == null) return;
        try {
            var data = new JSONObject();
            data.put("vm_id", getId().toString());
            data.put("vm_name", getName());
            data.put("state", state.name().toLowerCase());
            data.put("event", event);
            if (event.equals("exited")) {
                data.put("exit_code", exitCode);
                var sio = getStream("stdio");
                if (sio != null) data.put("stdio", sio.getBuffer());
            }
            if (extra != null) JsonUtils.mergeJSONObject(data, extra);
            cb.onVMEvent(getId().toString(), event, data);
        } catch (JSONException e) {
            Log.w(TAG, "Failed to build event data", e);
        }
    }

    public boolean runControlCommand(@NonNull String command) {
        if (waitsForGuestMemoryReclaim()) {
            synchronized (startLock) {
                var observed = process;
                if (observed == null || observed.isExitObserved()) return false;
                return getBackendInstance().runControlCommand(command) == 0;
            }
        }
        return getBackendInstance().runControlCommand(command) == 0;
    }

    /** Boot plan prepared for the current start; null when not started. */
    @Nullable
    public BootPlan getBootPlan() {
        return bootPlan;
    }

    /**
     * One-shot boot entry selection (id or title) from the GUI boot menu;
     * applies to the next {@link #start()} only and does not touch the
     * pinned entry in the config.
     */
    public void setBootEntryOverride(@Nullable String entryId) {
        bootEntryOverride = entryId;
    }

    /**
     * Takes this VM from STOPPED to STARTING and hands it to a worker thread.
     *
     * <p>Held under {@link #startLock} from the state test to the worker being handed the VM,
     * because two callers reaching here at once is no longer hypothetical: the auto-start sweep
     * runs behind the daemon's socket now, so a client's {@code vm_start} can arrive while the
     * sweep is looking at the same VM. Unlocked, both read STOPPED, both pass the test, and the
     * VM gets two worker threads and two crosvm processes against one set of taps and sockets.
     * The test alone cannot be made atomic -- it is the whole run-up to {@code setState} that has
     * to be, since that is what publishes the claim.</p>
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean start() {
        synchronized (startLock) {
            startError = null;
            // Loaded instances retain DataStore.load()'s parsing store. Admission belongs
            // to the registry on the shared context, where Stop All and shutdown run.
            var activeStore = store.context == null ? null : store.context.getVMs();
            if (activeStore == null) return refuseStart("The App VM registry is unavailable; a new VM cannot start");
            if (activeStore.isShuttingDown()) return refuseStart("The App is closing; a new VM cannot start");
            // REBOOTING is accepted too: the reboot relaunch calls start() from that
            // transient state (process already gone) and goes straight to STARTING.
            if (state != VMState.STOPPED && state != VMState.REBOOTING) {
                Log.w(TAG, fmt("VM %s is not stopped (state=%s), cannot start",
                    getId(), state.name()));
                return false;
            }
            if (AppRuntimeIdentity.current().isIsolatedApplication()) {
                try {
                    CrosvmHostPolicy.validateBackend(optEnum(item, "backend", VMBackend.DEFAULT),
                        AppRuntimeIdentity.current());
                    var status = PoolPreflight.check(item);
                    if (!status.isEnough()) return refuseStart(status.unavailableReason());
                    var capabilityProblem = AppleVmHostCapabilityAccess.acquireForVmStart(item);
                    if (capabilityProblem != null) return refuseStart(capabilityProblem);
                } catch (RuntimeException e) {
                    return refuseStart(e.getMessage());
                }
            }
            joinThreads(1000);
            if (!setupTaps()) return false;
            resolveVncConfig();
            stoppedByUser = false;
            exitCode = -1;
            setState(VMState.STARTING);
            var vmIdStr = getId().toString();
            workerThread = new Thread(this::runVM, fmt("VM-%s", vmIdStr));
            workerThread.setDaemon(true);
            workerThread.start();
            Log.i(TAG, fmt(
                "Start requested for VM: %s [%s] via %s",
                getName(), vmIdStr, getBackend().name()
            ));
            return true;
        }
    }

    @Nullable
    public String getStartError() {
        return startError;
    }

    private boolean refuseStart(@Nullable String reason) {
        startError = reason == null ? "Apple host-capability preflight failed" : reason;
        Log.e(TAG, startError);
        var stdio = getStream("stdio");
        if (stdio != null) stdio.appendBuffer(startError + "\n");
        return false;
    }

    private void setupTap(int index, List<DataItem> createdNics, @NonNull DataItem netCfg, String vmId) throws Exception {
        var nic = new VMNicConfig(netCfg);
        var netId = nic.getNetworkId();
        if (netId == null) return;
        var netInst = store.networkStore.findById(UUID.fromString(netId));
        if (netInst == null) throw new RuntimeException(fmt("Network %s not found", netId));
        var netState = netInst.getState();
        if (netState != NetworkState.RUNNING && !AppRuntimeIdentity.current().isIsolatedApplication()) {
            Log.i(TAG, fmt("Network %s is %s, attempting to start it", netId, netState));
            if (!netInst.start())
                throw new RuntimeException(netInst.getStartError() == null
                    ? fmt("Failed to start network %s", netId) : netInst.getStartError());
            netState = netInst.getState();
            if (netState != NetworkState.RUNNING)
                throw new RuntimeException(fmt("Network %s still not running after start (state=%s)", netId, netState));
            Log.i(TAG, fmt("Network %s started successfully", netId));
        }
        var tapName = nic.getTapName();
        if (AppRuntimeIdentity.current().isIsolatedApplication()) {
            tapName = AppRuntimeIdentity.current().tapName(vmId, index);
            nic.setTapName(tapName);
        }
        if (tapName == null) {
            tapName = fmt("vm%s-%d", vmId.substring(0, 8), index);
            nic.setTapName(tapName);
        }
        netInst.attachNic(nic, tapName);
        createdNics.add(netCfg);
        Log.i(TAG, fmt(
            "NIC %s attached to network %s for VM %s", tapName, netInst.getName(), vmId
        ));
    }

    private boolean setupTaps() {
        var nets = item.opt("networks", DataItem.newArray());
        if (nets.isEmpty()) return true;
        if (store.networkStore == null) {
            Log.e(TAG, fmt("VM %s has networks but no network store", getId()));
            return false;
        }
        var vmId = getId().toString();
        var createdNics = new ArrayList<DataItem>();
        try {
            var arr = nets.asArray();
            for (int i = 0; i < arr.size(); i++) {
                setupTap(i, createdNics, arr.get(i), vmId);
            }
        } catch (Exception e) {
            startError = e.getMessage();
            Log.e(TAG, fmt("Error setting up TAP for VM %s: %s", vmId, e.getMessage()), e);
            cleanupCreatedNics(createdNics);
            return false;
        }
        return true;
    }

    private void cleanupCreatedNics(@NonNull List<DataItem> nics) {
        for (var netCfg : nics)
            detachNic(new VMNicConfig(netCfg));
    }

    private void detachNic(@NonNull VMNicConfig nic) {
        var tapName = nic.getTapName();
        if (tapName == null) return;
        var netId = nic.getNetworkId();
        var netInst = netId != null
            ? store.networkStore.findById(UUID.fromString(netId)) : null;
        if (netInst != null) {
            netInst.detachNic(nic, tapName);
        } else {
            // network gone; remove the tap directly
            var net = store.networkStore.backend;
            net.removeInterface(tapName);
            net.deleteTap(tapName);
        }
    }

    /**
     * Fills in whatever each VNC-bound screen left unset before the VM starts.
     *
     * <p>Per screen, not per VM: two screens exporting over VNC are two servers, and crosvm
     * refuses to start when they land on the same port -- so an unset port is resolved once for
     * each of them, and the one just handed out is held against the next lookup because it is not
     * bound yet and would otherwise still look free.</p>
     */
    private void resolveVncConfig() {
        var taken = new ArrayList<Long>();
        for (var screen : VMScreenConfig.listOf(item)) {
            if (!screen.isEnabled() || screen.getExporter() != DisplayExporter.VNC) continue;
            var port = screen.getVncPort();
            if (port <= 0 || taken.contains(port)) {
                int fresh = generateRandomAvailablePort();
                while (fresh > 0 && taken.contains((long) fresh))
                    fresh = generateRandomAvailablePort();
                if (fresh > 0) {
                    screen.setVncPort(fresh);
                    port = fresh;
                    Log.i(TAG, fmt("VM %s: auto-assigned VNC port %d for screen %s",
                        getName(), fresh, screen.id));
                } else {
                    Log.e(TAG, fmt("VM %s: failed to find available VNC port for screen %s",
                        getName(), screen.id));
                }
            }
            if (port > 0) taken.add(port);
            if (screen.isVncPasswordAuth() && screen.getVncPassword().isEmpty()) {
                screen.setVncPassword(generateRandomPassword(8));
                Log.i(TAG, fmt("VM %s: auto-generated VNC password for screen %s",
                    getName(), screen.id));
            }
        }
    }

    public boolean stop() {
        synchronized (startLock) {
            if (state == VMState.REBOOTING) {
                // The previous run is finalized; cancel its pending relaunch without spawning it.
                stoppedByUser = true;
                rebootRequested = false;
                exitCode = 0;
                setState(VMState.STOPPED);
                fireEvent("exited", null);
                return true;
            }
            if (state != VMState.RUNNING && state != VMState.STARTING && state != VMState.SUSPENDED
                && !(state == VMState.STOPPING && waitsForGuestMemoryReclaim())) {
                Log.w(TAG, fmt("Cannot stop VM %s: state=%s", getId(), state.name()));
                return false;
            }
            stoppedByUser = true;
            setState(VMState.STOPPING);
            if (waitsForGuestMemoryReclaim()) {
                requestOrderedStopLocked(getBackendInstance(), process);
                return true;
            }
        }
        if (getBackendInstance().hasControlSocket()) {
            Log.i(TAG, fmt("Stopping VM %s via control socket", getName()));
            if (runControlCommand("stop")) return true;
            Log.w(TAG, fmt("Control stop request failed for VM %s", getName()));
        }
        var stoppingProcess = process;
        if (stoppingProcess != null && stoppingProcess.isAlive()) {
            Log.i(TAG, fmt("Destroying VM %s process", getName()));
            stoppingProcess.destroy();
            shellKillProcess(stoppingProcess.pid());
        }
        return true;
    }

    public boolean reboot() {
        synchronized (startLock) {
            if (state != VMState.RUNNING) {
                Log.w(TAG, fmt("Cannot reboot VM %s: state=%s", getId(), state.name()));
                return false;
            }
            Log.i(TAG, fmt("Reboot requested for VM %s", getName()));
            // The relaunch remains queued until the old memory owner actually exits.
            rebootRequested = true;
            if (waitsForGuestMemoryReclaim()) {
                setState(VMState.STOPPING);
                requestOrderedStopLocked(getBackendInstance(), process);
                return true;
            }
        }
        // crosvm has no reset control command, so reboot = ask crosvm to exit and
        // let runVM() relaunch via the rebootRequested flag (kept set on fallback).
        if (getBackendInstance().hasControlSocket()) {
            if (runControlCommand("stop")) return true;
            Log.w(TAG, fmt("Control stop request failed for reboot of VM %s", getName()));
        }
        if (process != null && process.isAlive()) {
            process.destroy();
            shellKillProcess(process.pid());
        }
        return true;
    }

    public boolean suspend() {
        if (state != VMState.RUNNING) {
            Log.w(TAG, fmt("Cannot suspend VM %s: state=%s", getId(), state.name()));
            return false;
        }
        if (runControlCommand("suspend")) {
            setState(VMState.SUSPENDED);
            return true;
        }
        return false;
    }

    public boolean resume() {
        if (state != VMState.SUSPENDED) {
            Log.w(TAG, fmt("Cannot resume VM %s: state=%s", getId(), state.name()));
            return false;
        }
        if (runControlCommand("resume")) {
            setState(VMState.RUNNING);
            return true;
        }
        return false;
    }

    @NonNull
    public List<String> getStreamNames() {
        return new ArrayList<>(getBackendInstance().streams.keySet());
    }

    @NonNull
    public List<ConsoleStream> getStreams() {
        return new ArrayList<>(getBackendInstance().streams.values());
    }

    @Nullable
    public ConsoleStream getStream(@NonNull String streamName) {
        return getBackendInstance().streams.get(streamName);
    }

    public void joinThreads(long timeoutMs) {
        if (timeoutMs == 0) {
            joinUntilExited(workerThread);
            for (var stream : getBackendInstance().streams.values())
                joinUntilExited(stream.getReaderThread());
            return;
        }
        if (workerThread != null && workerThread.isAlive()) {
            try {
                workerThread.join(timeoutMs);
            } catch (InterruptedException ignored) {
            }
        }
        for (var stream : getBackendInstance().streams.values()) {
            var reader = stream.getReaderThread();
            if (reader != null && reader.isAlive()) {
                try {
                    reader.join(timeoutMs);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }

    boolean waitsForGuestMemoryReclaim() {
        return getBackendInstance().waitsForGuestMemoryReclaim();
    }

    private static void joinUntilExited(@Nullable Thread thread) {
        if (thread == null || thread == Thread.currentThread()) return;
        boolean interrupted = false;
        try {
            while (thread.isAlive()) {
                try { thread.join(); }
                catch (InterruptedException e) { interrupted = true; }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    /** Capture and dispatch under startLock so a delayed caller cannot stop a later run. */
    private void requestOrderedStopLocked(VMBackendInstance inst, @Nullable NativeProcess observed) {
        if (observed == null || observed.isExitObserved()) return;
        try {
            if (inst.hasControlSocket() && inst.runControlCommand("stop") == 0) return;
        } catch (RuntimeException e) {
            Log.w(TAG, fmt("VM %s: control stop request will be retried", getName()), e);
        }
        queueOrderedStop(inst, observed);
    }

    /** This thread can request stop; only the worker's wait may finalize this run. */
    private void queueOrderedStop(VMBackendInstance inst, @Nullable NativeProcess observed) {
        if (observed == null || observed.isExitObserved()) return;
        synchronized (startLock) {
            if (stopRequestProcess == observed && stopRequestThread != null
                && stopRequestThread.isAlive()) return;
            stopRequestProcess = observed;
            var request = new VmStopRequestRetrier(observed::isExitObserved,
                () -> inst.runControlCommand("stop") == 0, () -> Thread.sleep(500));
            var thread = new Thread(request, "VMStopRequest-" + getId());
            thread.setDaemon(true);
            stopRequestThread = thread;
            thread.start();
        }
        Log.i(TAG, fmt("VM %s: stop request queued; waiting for the memory owner to exit", getName()));
    }

    public void clearLogs() {
        for (var stream : getStreams())
            stream.clear();
    }

    private void runVM() {
        var inst = getBackendInstance();
        boolean wantRestart = false;
        try {
            wantRestart = runVMProcess(inst);
        } catch (Exception e) {
            Log.e(TAG, fmt("VM %s: start/run failed", getName()), e);
            var sio = getStream("stdio");
            if (sio != null) sio.appendBuffer(fmt("VM start/run failed: %s\n", e.getMessage()));
            exitCode = stoppedByUser ? 0 : -1;
        } finally {
            // The same finalizer owns failed starts, cancellation and normal process exit.
            // Never release backend/TAP resources while this run's process can still use them.
            var remaining = process;
            if (remaining != null) {
                if (inst.waitsForGuestMemoryReclaim()) {
                    queueOrderedStop(inst, remaining);
                    remaining.waitFor();
                    if (stopRequestProcess == remaining) joinUntilExited(stopRequestThread);
                } else if (remaining.isAlive()) {
                    remaining.destroy();
                    shellKillProcess(remaining.pid());
                    remaining.waitFor();
                }
            }
            process = null;
            for (var stream : inst.streams.values()) {
                try {
                    stream.close();
                } catch (Exception e) {
                    Log.w(TAG, "Console cleanup failed", e);
                }
            }
            try {
                cleanupTap();
            } catch (Exception e) {
                Log.w(TAG, "TAP cleanup failed", e);
            } finally {
                try {
                    inst.cleanup();
                } catch (Exception e) {
                    Log.w(TAG, "Backend cleanup failed", e);
                }
                bootEntryOverride = null;
            }
            boolean relaunch;
            synchronized (startLock) {
                relaunch = wantRestart && !stoppedByUser;
                if (relaunch) {
                    rebootRequested = false;
                    exitCode = -1;
                    setState(VMState.REBOOTING);
                    fireEvent("rebooting", null);
                    Log.i(TAG, fmt("VM %s rebooting", getName()));
                } else {
                    if (remaining != null) nprocGuardResetBestEffort();
                    setState(VMState.STOPPED);
                    fireEvent("exited", null);
                }
            }
            if (relaunch) scheduleRelaunch();
        }
    }

    /** Runs a single process; resource finalization and final state belong to runVM(). */
    private boolean runVMProcess(@NonNull VMBackendInstance inst) {
        var vmId = getId().toString();
        try {
            // image-source boot runs lbx here (scan + cached extract), so
            // backends only ever see resolved kernel/initrd/cmdline paths
            bootPlan = BootPlan.resolve(this, bootEntryOverride);
        } catch (Exception e) {
            Log.e(TAG, fmt("VM %s: boot resolution failed", getName()), e);
            var sio = getStream("stdio");
            if (sio != null)
                sio.appendBuffer(fmt("boot resolution failed: %s\n", e.getMessage()));
            exitCode = stoppedByUser ? 0 : -1;
            return false;
        } finally {
            bootEntryOverride = null;
        }
        if (bootPlan.entryFallback)
            fireEvent("boot_entry_fallback", null);
        if (stoppedByUser || state != VMState.STARTING) {
            exitCode = 0;
            return false;
        }
        VMStartResult result;
        try {
            result = inst.start();
        } catch (Exception e) {
            Log.e(TAG, fmt("VM %s: exception during start vm", getName()), e);
            result = new VMStartResult();
            result.setProcess(null);
        }
        process = result.getProcess();
        if (!result.isSuccess()) {
            exitCode = stoppedByUser ? 0 : -1;
            return false;
        }
        for (var entry : inst.streams.entrySet()) {
            var stream = entry.getValue();
            if (stream.isReadable() && stream.getInputStream() != null)
                startReaderThread(vmId, stream);
        }
        boolean cancelled;
        synchronized (startLock) {
            cancelled = stoppedByUser || state != VMState.STARTING;
            if (!cancelled) setState(VMState.RUNNING);
        }
        if (cancelled) {
            if (inst.waitsForGuestMemoryReclaim()) queueOrderedStop(inst, process);
            else {
                process.destroy();
                shellKillProcess(process.pid());
            }
        }
        long ranFrom = System.currentTimeMillis();
        int code = process.waitFor();
        long ranForMs = System.currentTimeMillis() - ranFrom;
        // Complete console delivery before interpreting exit diagnostics (including pin failure).
        for (var stream : inst.streams.values()) {
            var reader = stream.getReaderThread();
            if (reader != null && reader.isAlive()) {
                try {
                    reader.join(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        exitCode = code;
        // A guest-requested reset (crosvm exit 32) or a host-issued reboot both
        // relaunch the VM; an explicit user stop never does and wins over both.
        boolean wantRestart = !stoppedByUser && (code == CrosvmExit.RESET.getCode() || rebootRequested);
        // ... and so does a start that died because the memory it was given could not be pinned.
        // That is the VMM refusing to hand the hypervisor pages the host may still move, and it
        // is worth exactly one more attempt: the condition is a moment in time (the reserve had
        // not finished taking the previous VM's pages back, or the allocation drew from CMA), and
        // measured on device the identical configuration started cleanly on the retry. Beyond one
        // attempt it is not a moment, it is a shortage, and repeating would only hide it.
        // RUNNING is set the moment the process is spawned, so it says nothing about whether the
        // VM got off the ground: a pin refusal happens inside VM creation, seconds later. A start
        // that lasted is what clears the one-shot, so a VM that ran for an hour and then died can
        // still be retried, while a VM failing in three seconds cannot loop.
        if (code == 0 || ranForMs > PIN_RETRY_RESET_MS) pinRetryUsed = false;
        boolean pinFailure = !stoppedByUser && !wantRestart && code != 0 && !pinRetryUsed
            && exitLogSuggestsPinFailure();
        if (pinFailure) {
            pinRetryUsed = true;
            wantRestart = true;
            Log.w(TAG, fmt("VM %s exited on unpinnable memory; retrying once", getName()));
        }
        if (stoppedByUser && code != 0) {
            Log.i(TAG, fmt("VM %s stopped by user", getName()));
            exitCode = 0;
        } else {
            Log.i(TAG, fmt("VM %s exited with code %d", getName(), code));
        }
        return wantRestart;
    }

    /**
     * Best-effort, run by the daemon once a VM's process has fully exited: ask nproc_guard to
     * recompute the app uid's RLIMIT_NPROC ucounts counter back to its true live count. crosvm
     * drops its real uid to the app's (setresuid, to reach the camera/mic/app-scoped files), and
     * on some kernels that real-uid switching leaves the per-uid NPROC accounting slightly off;
     * left to drift across many VM runs it eventually blocks the app from launching until a
     * reboot. Doing it here -- process gone, uid idle -- is the exact, race-free moment to correct
     * it. The guard module is loaded with this app's uid, so a bare "1" is enough; if it is not
     * loaded the sysfs node is absent and this is a no-op.
     */
    private static void nprocGuardResetBestEffort() {
        if (!AppRuntimeIdentity.current().allowsSharedHostMutation())
            return;
        var reset = new File("/sys/kernel/nproc_guard/reset");
        if (!reset.exists())
            return;
        try (var os = new FileOutputStream(reset)) {
            os.write('1');
        } catch (Exception e) {
            Log.d(TAG, "nproc_guard reset skipped", e);
        }
    }

    // Relaunch off the worker thread: start() joins workerThread (this thread),
    // and the short sleep settles same-name TAP recreation before re-setup.
    /**
     * Whether this exit was the VMM refusing memory it could not pin (see crosvm's pin.rs).
     *
     * Read off the console rather than the exit code, because there is no distinct code for it:
     * crosvm reports a plain failure to create the VM. The two lines below are the ones that
     * distinguish it from every other start failure -- a bad disk path, a missing kernel -- which
     * must not be retried.
     */
    private boolean exitLogSuggestsPinFailure() {
        var stream = getStream("stdio");
        if (stream == null) return false;
        var log = stream.getBuffer();
        if (log == null) return false;
        return log.contains("GH-PIN[") && log.contains("cannot be long-term pinned");
    }

    private void scheduleRelaunch() {
        var t = new Thread(() -> {
            try {
                Thread.sleep(REBOOT_RELAUNCH_DELAY_MS);
            } catch (InterruptedException ignored) {
                return;
            }
            if (state != VMState.REBOOTING) return; // user changed state meanwhile
            // The VM we are relaunching has only just let go of its memory, and the huge-page
            // reserve takes a few seconds to get it back. Relaunching into that gap is the one
            // way a reboot turns into a dead VM: the pages come from ordinary movable memory
            // instead, the VMM refuses to hand memory it cannot pin to the hypervisor, and the
            // relaunch exits with ENOMEM (measured: reserve at 526 of 2542 pages when the
            // relaunch started, full again nine seconds later). Nobody is watching a reboot, so
            // it waits like any other background start -- see PoolPreflight.waitForPool.
            if (!PoolPreflight.waitForPool(item, PoolPreflight.RELAUNCH_ATTEMPTS,
                PoolPreflight.BACKGROUND_INTERVAL_MS, PoolPreflight.BACKGROUND_ACQUIRE_AT))
                Log.w(TAG, fmt("VM %s relaunching with the reserve still short", getName()));
            if (state != VMState.REBOOTING) return; // stopped while we waited
            if (!start()) {
                Log.w(TAG, fmt("VM %s relaunch failed", getName()));
                // Surface the failure as a real exit so attached consoles / UI stop
                // waiting for the reboot to come back. start() left us in REBOOTING,
                // so settle to STOPPED before the exit fires the correct final state.
                exitCode = -1;
                setState(VMState.STOPPED);
                fireEvent("exited", null);
            }
        }, fmt("VM-relaunch-%s", getId()));
        t.setDaemon(true);
        t.start();
    }

    private void cleanupTap() {
        var nets = requireNonNull(item.opt("networks", DataItem.newArray()));
        if (nets.isEmpty()) return;
        for (var iter : nets) {
            var nic = new VMNicConfig(iter.getValue());
            if (nic.getTapName() == null) continue;
            Log.i(TAG, fmt("Cleaning up TAP %s for VM %s", nic.getTapName(), getName()));
            detachNic(nic);
        }
    }

    private void startReaderThread(@NonNull String vmId, @NonNull ConsoleStream stream) {
        var streamName = stream.getName();
        if (!stream.isReadable()) return;
        var reader = new Thread(
            () -> readStream(vmId, stream),
            fmt("Reader-%s-%s", vmId, streamName)
        );
        reader.setDaemon(true);
        stream.setReaderThread(reader);
        reader.start();
    }

    private void addStreamData(@NonNull ConsoleStream stream, @NonNull byte[] data, int len) {
        stream.appendBuffer(data, 0, len);
        try {
            var extra = new JSONObject();
            extra.put("stream", stream.getName());
            extra.put("data", urlEncodeBytesAll(data, 0, len));
            fireEvent("output", extra);
        } catch (JSONException ignored) {
        }
    }

    private void addStreamData(@NonNull String name, @NonNull byte[] data, int len) {
        var stream = getStream(name);
        if (stream != null) addStreamData(stream, data, len);
    }

    private void readStream(@NonNull String vmId, @NonNull ConsoleStream stream) {
        byte[] buf = new byte[4096];
        var streamName = stream.getName();
        if (!stream.isReadable()) return;
        var fd = stream.getPosixReadFd();
        var is = stream.getInputStream();
        try {
            int n;
            while (true) {
                if (fd > 0) {
                    int pollRet = UnixHelper.nativePollIn(fd, 1000);
                    if (pollRet < 0) break;
                    if (pollRet == 0) continue;
                    n = UnixHelper.nativeRead(fd, buf, buf.length);
                    if (n <= 0) break;
                } else if (is != null) {
                    n = is.read(buf);
                    if (n <= 0) break;
                } else break;
                addStreamData(streamName, buf, n);
                if (streamName.equals("stdout") || streamName.equals("stderr"))
                    addStreamData("stdio", buf, n);
            }
        } catch (Exception e) {
            Log.d(TAG, fmt("Stream reader %s for VM %s ended: %s", streamName, vmId, e.getMessage()));
        }
    }

    @NonNull
    public JSONObject toInfoJson() throws JSONException {
        var obj = item.toJson();
        obj.put("state", state.name());
        obj.put("pid", getPid());
        var streamNames = new JSONArray();
        for (var name : getBackendInstance().streams.keySet())
            streamNames.put(name);
        obj.put("streams", streamNames);
        return obj;
    }

    @NonNull
    static VMInstance getVMInstance(@NonNull VMInstanceStore store, @NonNull VMConfig config, @NonNull UUID vmId) {
        var inst = new VMInstance(store);
        inst.item.set(config.item);
        inst.setId(vmId.toString());
        return inst;
    }
}
