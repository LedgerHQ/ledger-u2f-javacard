package com.ledger.u2f;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class UtilsTest {

    @Test
    public void testCompareConstantTimeEmpty() {
        byte[] array1 = new byte[]{};
        byte[] array2 = new byte[]{0x01, 0x01, 0x01};
        short zero = (short)0;
        assertThat(FIDOUtils.compareConstantTime(array1, zero, array2, zero, zero), is(false));
    }

    @Test
    public void testCompareConstantTimeNonEqual() {
        byte[] array1 = new byte[]{0x01, 0x02, 0x01};
        byte[] array2 = new byte[]{0x01, 0x01, 0x01};
        short zero = (short)0;
        assertThat(FIDOUtils.compareConstantTime(array1, zero, array2, zero, (short)3), is(false));
    }

    @Test
    public void testCompareConstantTimeEqual() {
        byte[] array1 = new byte[]{0x0F, 0x01, 0x02, 0x03, 0x0F};
        byte[] array2 = new byte[]{0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00};
        assertThat(FIDOUtils.compareConstantTime(array1, (short)1, array2, (short)3, (short)3), is(true));
    }
}
