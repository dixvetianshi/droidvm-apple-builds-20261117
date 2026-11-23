// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm.backend;

import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.List;

/** The MMIO disks in extra_options need the same Android file-lock policy as VM disk slots. */
public final class CrosvmExtraDiskOptions {
    private static final String MMIO_BLOCK = "--virtio-mmio-block";

    private CrosvmExtraDiskOptions() {}

    /**
     * Normalize argv at execution, including configurations persisted by older APKs. Paths,
     * read-only choices and all unrelated options stay unchanged; no whitespace tokenization
     * occurs because a selected Android folder can contain spaces.
     */
    @NonNull
    public static List<String> forAndroidSharedStorage(@NonNull List<String> arguments) {
        var result = new ArrayList<String>(arguments.size());
        for (int index = 0; index < arguments.size(); index++) {
            var argument = arguments.get(index);
            if (MMIO_BLOCK.equals(argument) && index + 1 < arguments.size()
                && !arguments.get(index + 1).startsWith("--")) {
                result.add(argument);
                result.add(withoutFileLock(arguments.get(++index)));
            } else if (argument.startsWith(MMIO_BLOCK + "=")) {
                result.add(MMIO_BLOCK + "=" + withoutFileLock(argument.substring(MMIO_BLOCK.length() + 1)));
            } else {
                result.add(argument);
            }
        }
        return result;
    }

    @NonNull
    private static String withoutFileLock(@NonNull String diskOptions) {
        var fields = diskOptions.split(",", -1);
        // A malformed argument must still reach crosvm as malformed, not gain a synthetic path.
        if (fields[0].isEmpty()) return diskOptions;
        var result = new StringBuilder(fields[0]);
        boolean lockWritten = false;
        for (int index = 1; index < fields.length; index++) {
            var field = fields[index];
            if (field.startsWith("lock=")) {
                if (!lockWritten) result.append(",lock=false");
                lockWritten = true;
            } else {
                result.append(',').append(field);
            }
        }
        if (!lockWritten) result.append(",lock=false");
        return result.toString();
    }
}
