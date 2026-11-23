// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.lib.archive;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Objects;

/**
 * Replaces a regular file, seeking over wholly zero write buffers. Closing preserves the
 * logical length even when the last buffer was skipped. Reads still return the original
 * bytes; allocation savings depend on the destination filesystem's sparse-file support.
 */
public final class SparseFileOutputStream extends OutputStream {
    private final RandomAccessFile file;
    private boolean closed;

    public SparseFileOutputStream(@NonNull File target) throws IOException {
        file = new RandomAccessFile(target, "rw");
        // Skipped zeros must not expose bytes left by an older file at this path.
        try {
            file.setLength(0);
        } catch (IOException error) {
            try {
                file.close();
            } catch (IOException closingError) {
                error.addSuppressed(closingError);
            }
            throw error;
        }
    }

    @Override
    public void write(int value) throws IOException {
        requireOpen();
        if ((value & 0xff) == 0) file.seek(file.getFilePointer() + 1);
        else file.write(value);
    }

    @Override
    public void write(@NonNull byte[] bytes, int offset, int length) throws IOException {
        Objects.checkFromIndexSize(offset, length, bytes.length);
        requireOpen();
        for (int index = offset; index < offset + length; index++) {
            if (bytes[index] != 0) {
                file.write(bytes, offset, length);
                return;
            }
        }
        file.seek(file.getFilePointer() + length);
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        // Also close the handle if extending the zero tail fails, preserving both errors.
        try (var closingFile = file) {
            closingFile.setLength(closingFile.getFilePointer());
        }
    }

    private void requireOpen() throws IOException {
        if (closed) throw new IOException("SparseFileOutputStream closed");
    }
}
