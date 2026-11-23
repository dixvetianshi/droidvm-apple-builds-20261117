// SPDX-License-Identifier: GPL-3.0-or-later
package cn.classfun.droidvm.lib.pkg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.lang.reflect.InvocationTargetException;

/** Bounded resource admission tests: no macOS data-store conversion or target execution. */
public final class AppleMacPsciResourceTest {
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();

    private static void verify(File source) throws Exception {
        var method = AppleMacImportPreparation.class.getDeclaredMethod("verifyPsciKernelSource", File.class);
        method.setAccessible(true);
        try {
            method.invoke(null, source);
        } catch (InvocationTargetException failure) {
            if (failure.getCause() instanceof Exception)
                throw (Exception) failure.getCause();
            throw failure;
        }
    }

    private static File checkedResource() {
        var selected = System.getProperty("appleMacPsciTestResource");
        assumeTrue("The separately verified raw KC is an optional local test input", selected != null);
        var resource = new File(selected);
        assertTrue(resource.isFile());
        assertEquals(AppleMacImportPreparation.PSCI_KC_BYTES, resource.length());
        return resource;
    }

    @Test
    public void missingDirectoryAndWrongLengthResourcesAreRejectedBeforeConversion() throws Exception {
        assertThrows(IOException.class, () -> verify(null));
        assertThrows(IOException.class, () -> verify(temporary.getRoot()));
        assertThrows(IOException.class, () -> verify(new File(temporary.getRoot(), "missing-kc.bin")));
        var truncated = temporary.newFile("truncated-kc.bin");
        assertThrows(IOException.class, () -> verify(truncated));
        assertEquals(1, temporary.getRoot().list().length);
        assertEquals(0, truncated.length());
    }

    @Test
    public void sameLengthWrongKernelIsRejectedByActualHashCheck() throws Exception {
        var wrong = temporary.newFile("wrong-kc.bin");
        try (var file = new RandomAccessFile(wrong, "rw")) {
            file.setLength(AppleMacImportPreparation.PSCI_KC_BYTES);
        }
        assertThrows(IOException.class, () -> verify(wrong));
        assertEquals(AppleMacImportPreparation.PSCI_KC_BYTES, wrong.length());
        assertEquals(1, temporary.getRoot().list().length);
    }

    @Test
    public void actualPinnedRawKernelIsAcceptedWithoutChangingSource() throws Exception {
        var resource = checkedResource();
        long modified = resource.lastModified();
        verify(resource);
        assertEquals(AppleMacImportPreparation.PSCI_KC_BYTES, resource.length());
        assertEquals(modified, resource.lastModified());
        assertEquals(0, temporary.getRoot().list().length);
    }

    @Test
    public void interruptedAdmissionRejectsBeforeCreatingAnyDerivedFile() throws Exception {
        var resource = checkedResource();
        Thread.currentThread().interrupt();
        try {
            assertThrows(InterruptedIOException.class, () -> verify(resource));
        } finally {
            Thread.interrupted();
        }
        assertEquals(0, temporary.getRoot().list().length);
    }
}
