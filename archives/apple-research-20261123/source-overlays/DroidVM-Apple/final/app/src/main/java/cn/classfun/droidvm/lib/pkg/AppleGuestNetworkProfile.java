// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import cn.classfun.droidvm.lib.store.network.BridgeType;
import cn.classfun.droidvm.lib.store.network.NetworkConfig;
import cn.classfun.droidvm.lib.store.network.NetworkConfigValidator;
import cn.classfun.droidvm.lib.store.network.UplinkMode;

/**
 * The packaged Apple network recipe shared with the offline package generator. It uses the
 * existing gVisor L3 backend, whose empty DNS list selects Android's resolver proxy. A recipe
 * describes intended networking; it does not establish that a device has internet access.
 */
public final class AppleGuestNetworkProfile {
    private AppleGuestNetworkProfile() {}

    private static final class Recipe {
        static final String JSON = read();

        @NonNull
        private static String read() {
            try (var in = AppleGuestNetworkProfile.class.getResourceAsStream(
                "/apple-guest-network.json")) {
                if (in == null) throw new IOException("Apple guest network recipe is missing");
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read Apple guest network recipe", e);
            }
        }
    }

    /** Fresh package config; the import plan owns its eventual local id and bridge name. */
    @NonNull
    public static NetworkConfig create() {
        try {
            var config = new NetworkConfig(new JSONObject(Recipe.JSON));
            NetworkConfigValidator.validate(config);
            return config;
        } catch (JSONException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid Apple guest network recipe", e);
        }
    }

    /**
     * Recommend NAT for the original Apple package's Wi-Fi L2 ref before cards or import
     * decisions are built. Recognition belongs to AppleGuestImportProfile; neither the VM's
     * display name nor a network name establishes package identity. Other packaged networks
     * and a caller's already-routed config retain their values. No manifest or VM NIC is changed.
     */
    @NonNull
    static List<NetworkConfig> recommendedNetworks(@NonNull PackageManifest manifest) {
        if (AppleGuestImportProfile.identify(manifest) == null) return manifest.networks;
        var recipe = create();
        var ref = recipe.item.optString(NetworkImportPlan.REF_KEY, "");
        var out = new ArrayList<NetworkConfig>();
        for (var network : manifest.networks) {
            if (ref.equals(network.item.optString(NetworkImportPlan.REF_KEY, ""))
                && network.getBridgeType() == BridgeType.LINUX
                && network.getUplinkMode() == UplinkMode.L2)
                out.add(create());
            else out.add(network);
        }
        return out;
    }
}
