// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm.pkg;

import static cn.classfun.droidvm.daemon.vm.pkg.VMImportUtils.remapBootPaths;
import static cn.classfun.droidvm.daemon.vm.pkg.VMImportUtils.remapDiskPaths;
import static cn.classfun.droidvm.daemon.vm.pkg.VMImportUtils.uniqueFile;
import static cn.classfun.droidvm.lib.pkg.PackageConstants.BUFFER;
import static cn.classfun.droidvm.lib.utils.BinaryUtils.readFully;
import static cn.classfun.droidvm.lib.utils.NetUtils.generateRandomMac;
import static cn.classfun.droidvm.lib.utils.JsonUtils.listToJSONArray;
import static cn.classfun.droidvm.lib.utils.StringUtils.basename;
import static cn.classfun.droidvm.lib.utils.StringUtils.fmt;
import static cn.classfun.droidvm.lib.utils.StringUtils.safeFileName;
import static cn.classfun.droidvm.lib.utils.ThreadUtils.runOnPool;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import cn.classfun.droidvm.daemon.server.Server;
import cn.classfun.droidvm.lib.archive.SparseFileOutputStream;
import cn.classfun.droidvm.lib.archive.TarReader;
import cn.classfun.droidvm.lib.pkg.AppleGuestImportProfile;
import cn.classfun.droidvm.lib.pkg.AppleMacImportPreparation;
import cn.classfun.droidvm.lib.pkg.AppleMacPreparationResult;
import cn.classfun.droidvm.lib.pkg.BootFile;
import cn.classfun.droidvm.lib.pkg.DiskEntry;
import cn.classfun.droidvm.lib.pkg.NetworkImportPlan;
import cn.classfun.droidvm.lib.pkg.PackageConstants;
import cn.classfun.droidvm.lib.pkg.PackageFileChecksum;
import cn.classfun.droidvm.lib.pkg.PackageHeader;
import cn.classfun.droidvm.lib.pkg.PackageInput;
import cn.classfun.droidvm.lib.pkg.PackageManifest;
import cn.classfun.droidvm.lib.pkg.Phase;
import cn.classfun.droidvm.lib.pkg.VolumeSet;
import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.store.network.NetworkConfig;
import cn.classfun.droidvm.lib.store.vm.CpuPlacementPlan;
import cn.classfun.droidvm.lib.store.vm.NicLeaseOffsets;
import cn.classfun.droidvm.lib.store.vm.VMConfig;
import cn.classfun.droidvm.lib.store.vm.VMNicConfig;
import cn.classfun.droidvm.lib.utils.ImageUtils;

public final class VMImportTask {
    private static final String TAG = "VMImportTask";
    private static final long PROGRESS_INTERVAL_MS = 500;
    public final UUID taskId = UUID.randomUUID();
    private final Server server;
    private final String srcPath;
    private final File targetDir;
    /** What to do with a packaged network the plan says nothing about. */
    private final NetworkImportPlan.Action networkFallback;
    private final List<NetworkImportPlan.Entry> networkPlan;
    /** This package's own folder under {@link #targetDir}; created before the first file lands. */
    private File vmDir = null;
    private String vmName = "";
    private boolean registered = false;
    private int totalItems;
    private int volumeTotal = 0;
    private long lastPreparationEmit = 0;
    private AppleMacPreparationResult appleMacPreparation = null;
    public VMConfig importedVM = null;
    public PackageManifest importedManifest = null;
    public final ArrayList<DiskEntry> placedDisks = new ArrayList<>();
    public final ArrayList<BootFile> placedBoots = new ArrayList<>();

    public VMImportTask(@NonNull Server server, @NonNull JSONObject request) {
        this.server = server;
        srcPath = request.optString("src_path", "");
        if (!srcPath.startsWith("/"))
            throw new IllegalArgumentException("missing src_path");
        var targetPath = request.optString("target_dir", "");
        if (!targetPath.startsWith("/"))
            throw new IllegalArgumentException("missing target_dir");
        targetDir = new File(targetPath);
        networkPlan = NetworkImportPlan.parse(request.optJSONArray("network_plan"));
        // A caller with no plan gets the old whole-package behaviour: "skip" attaches nothing,
        // anything else recreates every network the package carries.
        networkFallback = request.optString("network_mode", "auto").equals("skip")
            ? NetworkImportPlan.Action.SKIP : NetworkImportPlan.Action.CREATE;
    }

    public void startAsync() {
        runOnPool(this::run);
    }

    private void run() {
        var data = DataItem.newObject();
        try {
            unpack();
            var networks = importNetworks(importedVM, NetworkImportPlan.packagedNetworks(importedManifest));
            resolveLeases(importedVM);
            var vmId = server.getContext().getVMs().createVM(importedVM);
            if (vmId == null || vmId.isEmpty()) throw new IOException("failed to register VM");
            registered = true;
            data.set("done", totalItems);
            data.set("total", totalItems);
            data.set("vm_id", vmId);
            data.set("vm_name", importedVM.getName());
            data.set("disks", listToJSONArray(placedDisks));
            data.set("boots", listToJSONArray(placedBoots));
            if (appleMacPreparation != null)
                data.set("macos_preparation", appleMacPreparation.toJson(importedVM.getId()));
            data.set("networks", networks);
            emit(data, Phase.DONE);
        } catch (Exception e) {
            Log.w(TAG, fmt("Import task %s failed", taskId), e);
            discardPlacedFiles();
            data.set("done", 0);
            data.set("total", totalItems);
            data.set("message", e.getMessage());
            emit(data, Phase.ERROR);
        } finally {
            server.getContext().getImportTaskStore().remove(taskId);
        }
    }

    private void onTarItem(
        @NonNull String name,
        int mode,
        long size,
        @NonNull InputStream content
    ) throws Exception{
        var disk = importedManifest.findDisk(name);
        if (disk != null) {
            if (size != disk.size) throw new IOException("Package disk size differs from its manifest");
            var target = ownedImportFile(vmDir, disk.name);
            disk.sha256Verified = false;
            disk.sha256Verified = copyEntry(content, target, size, placedDisks.size(), totalItems, disk.sha256);
            disk.target = target;
            placedDisks.add(disk);
            return;
        }
        var boot = importedManifest.findBoot(name);
        if (boot != null) {
            if (size != boot.size) throw new IOException("Package boot file size differs from its manifest");
            var dir = new File(vmDir, "boot");
            if (!dir.exists() && !dir.mkdirs())
                throw new IOException(fmt("Cannot create %s", dir));
            var target = ownedImportFile(dir, boot.name);
            var count = placedDisks.size() + placedBoots.size();
            boot.sha256Verified = false;
            boot.sha256Verified = copyEntry(content, target, size, count, totalItems, boot.sha256);
            boot.target = target;
            placedBoots.add(boot);
        }
    }

    private void unpack() throws Exception {
        // The metadata master can be checked without opening compressed disk data,
        // including for a multi-volume package. Refuse known old iPad boots before
        // creating any import directory or starting a disk/decompression stream.
        var masterPath = VolumeSet.masterOf(srcPath);
        try (var metadata = new FileInputStream(masterPath)) {
            requireSupportedSource(metadata);
        }
        if (!targetDir.exists() && !targetDir.mkdirs())
            throw new IOException(fmt("Cannot create target dir: %s", targetDir));
        // Any picked path maps to its metadata master (strip a .NNN suffix).
        if (readVolumeCount(masterPath) > 0) {
            var set = VolumeSet.discover(masterPath);
            volumeTotal = set.count();
            try (
                var in = set.openLogicalStream();
                var pkg = PackageInput.open(in, set.dataSize())
            ) {
                extract(pkg);
            }
        } else {
            try (
                var in = new FileInputStream(masterPath);
                var pkg = PackageInput.open(in)
            ) {
                extract(pkg);
            }
        }
        // Identify the verified package once; only this owner can produce preparation facts.
        var appleProfile = AppleGuestImportProfile.identify(importedManifest);
        appleMacPreparation = AppleMacImportPreparation.prepare(appleProfile, placedDisks,
            placedBoots, vmDir, new File(cn.classfun.droidvm.lib.Constants.PATH_MACOS_PSCI_KC), this::onMacPreparationProgress);
        var vm = new VMConfig(importedManifest.vm.toJson());
        vm.setId(UUID.randomUUID());
        vm.setName(vmName);
        relinkBackingChains();
        appleMacPreparation = completeConfiguration(appleProfile, vm, placedDisks, placedBoots,
            totalItems, appleProfile == null ? -1 : Server.getDroidVMUid(), appleMacPreparation);
        importedVM = vm;
    }

    static void requireSupportedSource(@NonNull InputStream metadata) throws Exception {
        AppleGuestImportProfile.requireSupportedImport(PackageInput.peekManifest(metadata));
    }

    /**
     * Finish the config before createVM can expose it to any console/start entry point. The UI
     * persists this same daemon config; it does not reinterpret package paths or runtime UIDs.
     */
    @Nullable
    static AppleMacPreparationResult completeConfiguration(
        @Nullable AppleGuestImportProfile.Guest appleProfile, @NonNull VMConfig vm,
        @NonNull ArrayList<DiskEntry> placedDisks, @NonNull ArrayList<BootFile> placedBoots,
        int totalItems, int appUid, @Nullable AppleMacPreparationResult preparation
    ) throws IOException {
        // ref.path/path now describe the completed placement, including a prepared Mac disk.
        // Source archive sizes and hashes remain provenance rather than derived-file claims.
        for (var disk : placedDisks)
            if (disk.target != null && disk.ref != null) disk.ref.path = disk.target.getPath();
        for (var boot : placedBoots)
            if (boot.target != null) boot.path = boot.target.getPath();
        remapDiskPaths(vm, placedDisks);
        remapBootPaths(vm, placedBoots);
        if (appleProfile != null) {
            if (preparation != null) {
                preparation = preparation.bindToVM(vm.getId());
                vm.item.set("memory_mb", 4096);
                vm.item.set("auto_up", false);
            }
            AppleGuestImportProfile.bind(appleProfile, vm, placedDisks, placedBoots,
                totalItems, totalItems, appUid, preparation);
        }
        // This normalization previously ran for every UI import. Keep the same choice, but
        // make its owning config identical in the daemon and in the subsequently saved store.
        CpuPlacementPlan.normalizeGpuCgroup(vm.item);
        return preparation;
    }

    /**
     * Re-point each imported overlay at the copy of its backing image that travelled with it.
     * The packed header still names the exporting phone's path - exporting reads the source
     * images and never rewrites them - so this is where a chain becomes usable again. Header
     * only: the data is already there, the files just live somewhere else now.
     */
    private void relinkBackingChains() throws IOException {
        var byArchive = new HashMap<String, DiskEntry>();
        for (var disk : placedDisks) byArchive.put(disk.archivePath, disk);
        for (var disk : placedDisks) {
            if (disk.backingArchive.isEmpty() || disk.target == null) continue;
            var parent = byArchive.get(disk.backingArchive);
            if (parent == null || parent.target == null) throw new IOException(fmt(
                "package is missing the backing image %s needed by %s",
                disk.backingArchive, disk.archivePath
            ));
            ImageUtils.rebaseBacking(disk.target.getPath(), parent.target.getPath());
            // The copied digest described the exporting file, before this header mutation.
            disk.sha256Verified = false;
        }
    }

    /**
     * Drop what a failed import wrote. Safe to do bluntly because everything it wrote is inside
     * one folder this import created for itself; nothing else has ever been in there.
     */
    private void discardPlacedFiles() {
        var dir = vmDir;
        if (dir == null || registered) return;
        vmDir = null;
        try {
            deleteTree(dir);
        } catch (Exception e) {
            Log.w(TAG, fmt("Failed to clean up %s", dir), e);
        }
    }

    private static void deleteTree(@NonNull File file) {
        var children = file.listFiles();
        if (children != null) for (var child : children) deleteTree(child);
        //noinspection ResultOfMethodCallIgnored
        file.delete();
    }

    /**
     * The folder this package's files go in: named after the VM, unique within the chosen
     * import folder. One package's disks - a backing chain can be several - stay together
     * instead of piling into a folder shared with every other VM's images.
     */
    @NonNull
    private File createVMDir(@NonNull String name) throws IOException {
        var base = safeFileName(name, "vm");
        var dir = new File(targetDir, base);
        for (int i = 1; dir.exists(); i++)
            dir = new File(targetDir, fmt("%s_%d", base, i));
        if (!dir.mkdirs())
            throw new IOException(fmt("Cannot create %s", dir));
        return dir;
    }

    private int readVolumeCount(@NonNull String masterPath) throws Exception {
        try (var in = new FileInputStream(masterPath)) {
            var hdr = new byte[PackageConstants.HEADER_SIZE];
            readFully(in, hdr);
            return PackageHeader.fromBytes(hdr).volumeCount;
        }
    }

    private void extract(@NonNull PackageInput pkg) throws Exception {
        importedManifest = pkg.manifest;
        AppleGuestImportProfile.requireSupportedImport(importedManifest);
        // Settle the name and make the folder before any byte lands in it, so the files are
        // together from the start and a failure has exactly one thing to clean up.
        vmName = uniqueVMName(importedManifest.vm.getName());
        vmDir = createVMDir(vmName);
        totalItems = importedManifest.disks.size() + importedManifest.boots.size();
        var data = DataItem.newObject();
        data.set("done", 0);
        data.set("total", totalItems);
        emit(data, Phase.PACK);
        var tar = new TarReader(pkg.data);
        tar.forEach(this::onTarItem);
        var buf = new byte[BUFFER];
        //noinspection StatementWithEmptyBody
        while (pkg.data.read(buf) >= 0);
        pkg.validateDataConsumed();
    }

    /**
     * Applies the import plan: each network the package carries is joined to one this phone
     * already has, created here, or left behind, and every NIC that referenced it is re-pointed
     * at what it ended up on. A NIC whose network was skipped -- or whose join target has since
     * been deleted -- comes out unattached rather than pointing at nothing.
     *
     * @return the networks this import created, for the caller to persist
     */
    @NonNull
    private JSONArray importNetworks(
        @NonNull VMConfig vm,
        @NonNull List<NetworkConfig> configs
    ) throws Exception {
        var refs = new HashMap<String, String>();
        var created = new JSONArray();
        var store = server.getContext().getNetworks();
        var plan = new NetworkImportPlan(store);
        for (var source : configs) {
            var ref = source.item.optString(NetworkImportPlan.REF_KEY, "");
            if (ref.isEmpty()) continue;
            var entry = NetworkImportPlan.findRef(networkPlan, ref);
            var action = entry == null ? networkFallback : entry.action;
            if (action == NetworkImportPlan.Action.SKIP) continue;
            if (action == NetworkImportPlan.Action.JOIN) {
                var target = entry == null || entry.networkId == null
                    ? null : store.findById(entry.networkId);
                if (target == null) {
                    Log.w(TAG, fmt("Import %s: no network to join for %s", taskId, ref));
                    continue;
                }
                refs.put(ref, target.getId().toString());
                continue;
            }
            // The screen prepared the config so the user could see what it would be; take it,
            // but let the plan settle the names again against the store as it is right now.
            var cfg = entry != null && entry.config != null
                ? plan.adopt(entry.config) : plan.prepareCreate(source);
            var id = store.createNetwork(cfg);
            if (id == null || id.isEmpty()) continue;
            refs.put(ref, id);
            created.put(cfg.toJson());
        }
        remapNetworks(vm, refs);
        return created;
    }

    private void remapNetworks(
        @NonNull VMConfig vm,
        @NonNull HashMap<String, String> refs
    ) {
        var nets = vm.item.opt("networks", null);
        if (nets == null || !nets.is(DataItem.Type.ARRAY)) return;
        for (var nic : nets.asArray()) {
            if (!nic.is(DataItem.Type.OBJECT)) continue;
            var ref = nic.optString(NetworkImportPlan.REF_KEY, "");
            nic.remove(NetworkImportPlan.REF_KEY);
            var id = refs.get(ref);
            if (id == null || id.isEmpty()) nic.remove("network_id");
            else nic.set("network_id", id);
        }
    }

    /**
     * Makes every static DHCP lease the package brought fit the network its NIC actually landed
     * on. An offset that came from the other phone is kept where it can be: it is what the guest
     * has been answering on. Where it cannot -- another VM here already holds it, it falls inside
     * this VLAN's dynamic pool, or the VLAN is smaller than it was over there -- the next free
     * offset is taken instead, and only when the VLAN has nothing free at all (or does not serve
     * that family, or the NIC ended up on no network) does the lease go back to a dynamic
     * address. Refusing the import over an address a VM can perfectly well be given by DHCP
     * would help nobody.
     */
    private void resolveLeases(@NonNull VMConfig vm) {
        vm.forEachNic(nic -> {
            resolveLease(vm, nic, NicLeaseOffsets.Family.IPV4);
            resolveLease(vm, nic, NicLeaseOffsets.Family.IPV6);
        });
    }

    private void resolveLease(
        @NonNull VMConfig vm,
        @NonNull VMNicConfig nic,
        @NonNull NicLeaseOffsets.Family family
    ) {
        boolean ipv6 = family == NicLeaseOffsets.Family.IPV6;
        if (!(ipv6 ? nic.isDhcp6LeaseEnabled() : nic.isDhcp4LeaseEnabled())) return;
        var netId = nic.getNetworkId();
        var network = netId == null ? null : server.getContext().getNetworks().findById(netId);
        var vlan = network == null ? null : nic.resolveDhcpVlan(network);
        if (vlan == null || !(ipv6 ? vlan.isDhcp6Enabled() : vlan.isDhcp4Enabled())) {
            nic.setDhcpLeaseEnabled(ipv6, false);
            return;
        }
        var used = new HashSet<Long>();
        server.getContext().getVMs().forEach((id, other) ->
            NicLeaseOffsets.addOffsets(used, other, network, vlan, family));
        // this VM is not registered yet, so its own other NICs are only in the config in hand
        NicLeaseOffsets.addOffsets(used, vm, network, vlan, family, nic);
        boolean has = ipv6 ? nic.hasDhcp6Offset() : nic.hasDhcp4Offset();
        long wanted = !has ? NicLeaseOffsets.FIRST
            : (ipv6 ? nic.getDhcp6Offset() : nic.getDhcp4Offset());
        long offset = NicLeaseOffsets.resolve(wanted, used, vlan, family);
        if (offset < 0) {
            Log.w(TAG, fmt("Import %s: no free lease offset on network %s", taskId, netId));
            nic.setDhcpLeaseEnabled(ipv6, false);
            return;
        }
        if (ipv6) nic.setDhcp6Offset(offset);
        else nic.setDhcp4Offset(offset);
        // Exporting strips NIC MAC addresses -- two phones must not hand out the same one -- but
        // a static lease is keyed by MAC, so a kept lease needs one now rather than whenever the
        // user next opens the NIC editor.
        if (nic.getMacAddress() == null) nic.item.set("mac_address", generateRandomMac());
    }

    private boolean copyEntry(
        @NonNull InputStream in,
        @NonNull File out,
        long size,
        int doneItems,
        int totalItems,
        @NonNull String expectedSha256
    ) throws IOException {
        var checksum = new PackageFileChecksum(expectedSha256);
        var data = DataItem.newObject();
        data.set("done", doneItems);
        data.set("total", totalItems);
        data.set("file", basename(out.getPath()));
        data.set("bytes_done", 0);
        data.set("bytes_total", size);
        emit(data, Phase.PACK);
        try (var os = new SparseFileOutputStream(out)) {
            var buf = new byte[BUFFER];
            long rem = size;
            long written = 0;
            long lastEmit = System.currentTimeMillis();
            while (rem > 0) {
                int toRead = (int) Math.min(buf.length, rem);
                int n = in.read(buf, 0, toRead);
                if (n <= 0) throw new IOException(fmt(
                    "entry %s: short read", out.getName()
                ));
                os.write(buf, 0, n);
                checksum.update(buf, 0, n);
                rem -= n;
                written += n;
                var now = System.currentTimeMillis();
                if (now - lastEmit >= PROGRESS_INTERVAL_MS) {
                    data.set("bytes_done", written);
                    emit(data, Phase.PACK);
                    lastEmit = now;
                }
            }
        }
        boolean verified = checksum.verify();
        data.set("done", doneItems + 1);
        data.set("bytes_done", size);
        emit(data, Phase.PACK);
        return verified;
    }

    private void onMacPreparationProgress(String operation, long done, long total, long extraBytes) {
        var now = System.currentTimeMillis();
        if (done != 0 && done != total && now - lastPreparationEmit < PROGRESS_INTERVAL_MS) return;
        lastPreparationEmit = now;
        var data = DataItem.newObject();
        data.set("done", totalItems);
        data.set("total", totalItems);
        data.set("file", operation + (extraBytes > 0 ? String.format(Locale.ROOT,
            " (temporarily needs %.1f GiB extra)", extraBytes / (double) (1L << 30)) : ""));
        data.set("bytes_done", done);
        data.set("bytes_total", total);
        data.set("preparation_extra_bytes", extraBytes);
        emit(data, Phase.PACK);
    }

    /** A manifest member supplies a file name, never a path outside this import's directory. */
    static File ownedImportFile(File directory, String name) throws IOException {
        if (name == null || name.isEmpty() || name.equals(".") || name.equals("..")
            || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || new File(name).isAbsolute())
            throw new IOException("Package member name must be a single file name");
        var target = uniqueFile(directory, name);
        if (!directory.getCanonicalFile().equals(target.getCanonicalFile().getParentFile()))
            throw new IOException("Package member target is outside its new import directory");
        return target;
    }

    @NonNull
    private String uniqueVMName(@NonNull String name) {
        var store = server.getContext().getVMs();
        if (store.findByName(name) == null) return name;
        int i = 1;
        while (store.findByName(fmt("%s (%d)", name, i)) != null) i++;
        return fmt("%s (%d)", name, i);
    }

    private void emit(@NonNull DataItem item, @NonNull Phase phase) {
        try {
            var data = item.toJson();
            data.put("event", "vm_import_status");
            data.put("task_id", taskId.toString());
            data.put("phase", phase.name().toLowerCase());
            if (volumeTotal > 0) data.put("volume_total", volumeTotal);
            var ev = new JSONObject();
            ev.put("type", "event");
            ev.put("data", data);
            server.broadcastEvent(ev);
        } catch (Exception e) {
            Log.w(TAG, fmt("Failed to emit import event for %s", taskId), e);
        }
    }
}
