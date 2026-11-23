// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
package cn.classfun.droidvm.daemon.vm.pkg;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class VMImportTaskOwnershipTest {
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void targetResolutionRefusesExternalAndNestedPathsBeforeAnyFileIsCreated() throws Exception {
        var owned = temporary.newFolder("new-import");
        var other = temporary.newFolder("existing-vm");
        var existing = new File(other, "keep.img");
        Files.write(existing.toPath(), new byte[]{1, 2, 3});
        for (String name : new String[]{null, "", ".", "..", "../existing-vm/new.img",
            "..\\existing-vm\\new.img", "nested/new.img", "/absolute.img"}) {
            assertThrows(IOException.class, () -> VMImportTask.ownedImportFile(owned, name));
        }
        assertEquals(0, owned.list().length);
        assertEquals(1, other.list().length);
        assertArrayEquals(new byte[]{1, 2, 3}, Files.readAllBytes(existing.toPath()));
    }

    @Test
    public void callerBasenamesArePreservedAndCollisionsStayInsideTheOwningDirectory() throws Exception {
        var owned = temporary.newFolder("new-import");
        var first = VMImportTask.ownedImportFile(owned, "macOS 数据.img");
        assertEquals("macOS 数据.img", first.getName());
        assertEquals(owned.getCanonicalFile(), first.getCanonicalFile().getParentFile());
        assertFalse(first.exists());
        Files.write(first.toPath(), new byte[]{8});
        var second = VMImportTask.ownedImportFile(owned, "macOS 数据.img");
        assertEquals("macOS 数据_1.img", second.getName());
        assertEquals(owned.getCanonicalFile(), second.getCanonicalFile().getParentFile());
        assertFalse(second.exists());
        assertArrayEquals(new byte[]{8}, Files.readAllBytes(first.toPath()));
    }
}
