package com.ledger.u2f;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class SimulatorTestBase {
    JavaxSmartCardInterface sim;
    AID aid;

    static final byte[] AIDArray = {(byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x17, (byte) 0x00, (byte) 0x4f, (byte) 0x97, (byte) 0xa2, (byte) 0xe9, (byte) 0x49, (byte) 0x01};

    @BeforeClass
    public static void setUpClass() {

    }

    @Before
    public void setUp() {
        sim = new JavaxSmartCardInterface();
    }

    public void prepareApplet(byte[] installData) {
        aid = new AID(AIDArray, (short) 0, (byte) AIDArray.length);
        byte[] fullData = new byte[2 + AIDArray.length + 1 + installData.length + 1];
        int offset = 0;
        fullData[offset++] = (byte) AIDArray.length;
        System.arraycopy(AIDArray, 0, fullData, offset, AIDArray.length);
        offset += AIDArray.length;
        fullData[offset++] = 0;
        fullData[offset++] = (byte) installData.length;
        System.arraycopy(installData, 0, fullData, offset, installData.length);
        aid = sim.installApplet(aid, U2FApplet.class, fullData, (short) 0, (byte) fullData.length);
        sim.selectApplet(aid);
    }

    @After
    public void tearDown() {
        sim.reset();
        sim.resetRuntime();
    }

    @AfterClass
    public static void tearDownClass() {

    }
}
