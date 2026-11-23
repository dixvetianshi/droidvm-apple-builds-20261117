package cn.classfun.droidvm.daemon.vm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import cn.classfun.droidvm.lib.store.base.DataItem;
import cn.classfun.droidvm.lib.utils.AppRuntimeIdentity;

public class UsbAcmPoolTest {
    @Test
    public void appleCannotEnableSharedGadgetEvenWithAnImportedEnabledSetting() {
        assertTrue(AppRuntimeIdentity.current().isIsolatedApplication());
        var config = DataItem.newObject();
        config.set(UsbAcmPool.KEY_USB_ACM_ENABLE, true);
        config.set(UsbAcmPool.KEY_USB_ACM_PORTS, 6);
        var before = new DataItem(config);
        assertFalse(UsbAcmPool.isSupported());
        assertFalse(UsbAcmPool.enabledOf(config));
        UsbAcmPool.applyConfig(config);
        assertEquals(before, config);
    }

    @Test
    public void appleRejectsAcquireBeforeSlotSelectionOrGadgetAccess() {
        var config = DataItem.newObject();
        config.set(UsbAcmPool.KEY_USB_ACM_ENABLE, true);
        for (int slot : new int[] {-1, 0, 99}) {
            var failure = assertThrows(UsbAcmPool.SlotUnavailableException.class,
                () -> UsbAcmPool.acquire(slot, "test-owner", config));
            assertTrue(failure.getMessage().contains("unavailable in DroidVM Apple"));
        }
    }

    @Test
    public void savingDisabledSettingsDoesNotReconcileTheOriginalAppsPool() {
        var config = DataItem.newObject();
        config.set(UsbAcmPool.KEY_USB_ACM_ENABLE, false);
        var before = new DataItem(config);
        UsbAcmPool.applyConfig(config);
        assertEquals(before, config);
        assertFalse(UsbAcmPool.enabledOf(config));
    }
}
