// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;

import cn.classfun.droidvm.lib.store.base.JSONSerialize;

public final class BootFile implements JSONSerialize {
    public String archivePath = null;
    public String name = null;
    public String path = null;
    public String kind = null;
    public long size = 0;
    public String sha256 = "";
    public boolean sha256Verified = false;
    public File target = null;

    public BootFile() {
    }

    public BootFile(@NonNull JSONObject o) {
        archivePath = o.optString("archive_path");
        name = o.optString("name");
        path = o.optString("path");
        kind = o.optString("kind");
        size = o.optLong("size");
        sha256 = PackageFileChecksum.readDeclared(o);
        sha256Verified = o.optBoolean("sha256_verified", false);
    }

    @NonNull
    @Override
    public JSONObject toJson() throws JSONException {
        var b = new JSONObject();
        b.put("archive_path", archivePath);
        b.put("name", target == null ? name : target.getName());
        b.put("path", target == null ? path : target.getPath());
        b.put("kind", kind);
        b.put("size", size);
        if (!sha256.isEmpty()) {
            b.put("sha256", sha256);
            b.put("sha256_verified", sha256Verified);
        }
        return b;
    }

    public boolean isExists() {
        var f = new File(path);
        return f.exists() && f.isFile();
    }

    public void build() {
        var f = new File(path);
        name = f.getName();
        archivePath = name;
        size = f.length();
    }

    @NonNull
    public static BootFile from(Object o) throws JSONException {
        if (o instanceof JSONObject)
            return new BootFile((JSONObject) o);
        throw new JSONException("object is not json");
    }
}
