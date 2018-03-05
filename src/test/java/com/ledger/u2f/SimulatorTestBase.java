package com.ledger.u2f;

import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;
import javacard.framework.Applet;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class SimulatorTestBase {
    CardSimulator sim;
    static final AID aid = new AID(new byte[]{(byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x17, (byte) 0x00, (byte) 0x4f, (byte) 0x97, (byte) 0xa2, (byte) 0xe9, (byte) 0x49, (byte) 0x01}, (short) 0, (byte) 12);

    @BeforeClass
    public static void setUpClass() {

    }

    @Before
    public void setUp() {
        //System.setProperty("com.licel.jcardsim.card.applet.0.AID", "a000000617004f97a2e94901");
        //System.setProperty("com.licel.jcardsim.card.applet.0.Class", "com.ledger.u2f.U2FApplet");
        sim = new CardSimulator();
    }

    public AID prepareApplet(byte[] installData, Class<? extends Applet> cls) {
        AID result = sim.installApplet(aid, cls, installData, (short) 0, (byte) installData.length);
        sim.selectApplet(result);
        return result;
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
