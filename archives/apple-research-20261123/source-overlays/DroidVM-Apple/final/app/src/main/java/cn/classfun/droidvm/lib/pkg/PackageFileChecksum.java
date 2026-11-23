// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.pkg;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONObject;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Optional publisher SHA-256, verified while the importer already copies a member. */
public final class PackageFileChecksum {
    private final String expected;
    @Nullable private final MessageDigest digest;

    public PackageFileChecksum(@Nullable String declaredSha256) {
        expected = validate(declaredSha256);
        try {
            digest = expected.isEmpty() ? null : MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    @NonNull
    public static String readDeclared(@NonNull JSONObject json) {
        var value = json.opt("sha256");
        if (value == null || value == JSONObject.NULL) return "";
        if (!(value instanceof String))
            throw new IllegalArgumentException("Package member SHA-256 must be a string");
        return validate((String) value);
    }

    @NonNull
    private static String validate(@Nullable String value) {
        if (value == null || value.isEmpty()) return "";
        if (!value.matches("[0-9a-fA-F]{64}"))
            throw new IllegalArgumentException("Package member SHA-256 must contain 64 hexadecimal digits");
        return value;
    }

    public void update(@NonNull byte[] bytes, int offset, int length) {
        if (digest != null) digest.update(bytes, offset, length);
    }

    /** False means the legacy manifest omitted the digest, never that its bytes were verified. */
    public boolean verify() throws IOException {
        if (digest == null) return false;
        var actual = new StringBuilder(64);
        for (byte value : digest.digest()) {
            actual.append(Character.forDigit((value >>> 4) & 15, 16));
            actual.append(Character.forDigit(value & 15, 16));
        }
        if (!expected.equalsIgnoreCase(actual.toString()))
            throw new IOException("Package member SHA-256 mismatch");
        return true;
    }
}
