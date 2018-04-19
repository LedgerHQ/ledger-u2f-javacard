package com.ledger.u2f;

import apdu4j.ISO7816;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class SimulatorTestBase {
    static JavaxSmartCardInterface sim;
    static final byte[] AIDArray = {(byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x17, (byte) 0x00, (byte) 0x4f, (byte) 0x97, (byte) 0xa2, (byte) 0xe9, (byte) 0x49, (byte) 0x01};
    static final AID aid = new AID(AIDArray, (short) 0, (byte) AIDArray.length);

    static final byte FIDO_CLA = (byte) 0x00;
    static final byte FIDO_INS_ENROLL = (byte) 0x01;
    static final byte FIDO_INS_SIGN = (byte) 0x02;
    static final byte FIDO_INS_VERSION = (byte) 0x03;
    static final byte PROPRIETARY_CLA = (byte) 0xF0;
    static final byte ISO_INS_GET_DATA = (byte) 0xC0;
    static final byte FIDO_ADM_SET_ATTESTATION_CERT = (byte) 0x01;
    static final byte P1_SIGN_OPERATION = (byte) 0x03;
    static final byte P1_SIGN_CHECK_ONLY = (byte) 0x07;
    static final int FIDO_SW_TEST_OF_PRESENCE_REQUIRED = 0x6985;
    static final int FIDO_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;
    static final byte INSTALL_FLAG_ENABLE_USER_PRESENCE = (byte) 0;
    static final byte INSTALL_FLAG_DISABLE_USER_PRESENCE = (byte) 0x01;


    @BeforeClass
    public static void setUpClass() {
        sim = new JavaxSmartCardInterface();
    }

    @Before
    public void setUp() {
    }

    public void prepareApplet(byte[] installData) {
        // Setup the GlobalPlatform install data format.
        byte[] fullData = new byte[2 + AIDArray.length + 1 + installData.length + 1];
        int offset = 0;
        fullData[offset++] = (byte) AIDArray.length;
        System.arraycopy(AIDArray, 0, fullData, offset, AIDArray.length);
        offset += AIDArray.length;
        fullData[offset++] = 0;
        fullData[offset++] = (byte) installData.length;
        System.arraycopy(installData, 0, fullData, offset, installData.length);

        sim.installApplet(aid, U2FApplet.class, fullData, (short) 0, (byte) fullData.length);
        sim.selectApplet(aid);
    }

    public void prepareApplet(byte flags, int attestationCertLength, byte[] attestationPrivKey) {
        byte[] installData = new byte[35];
        installData[0] = flags;
        installData[1] = (byte) ((attestationCertLength & 0xff00) >> 8);
        installData[2] = (byte) (attestationCertLength & 0xff);
        System.arraycopy(attestationPrivKey, 0, installData, 3, 32);

        prepareApplet(installData);
    }

    public byte[] sendGetData(int ne) {
        List<byte[]> responses = new LinkedList<>();
        CommandAPDU cmd = new CommandAPDU(FIDO_CLA, ISO_INS_GET_DATA, 0, 0, ne);
        do {
            ResponseAPDU getDataAPDU = sim.transmitCommand(cmd);
            responses.add(getDataAPDU.getData());
            int nr = getDataAPDU.getNr();

            assertThat(nr, lessThanOrEqualTo(ne));
            int sw = getDataAPDU.getSW();
            if (sw == ISO7816.SW_NO_ERROR) {
                break;
            }

            if (ne == 256) {
                assertThat(sw, allOf(greaterThanOrEqualTo(ISO7816.SW_BYTES_REMAINING_00), lessThanOrEqualTo(ISO7816.SW_BYTES_REMAINING_00 + 256)));
            } else {
                assertThat(sw, is(ISO7816.SW_NO_ERROR));
                break;
            }

            if (getDataAPDU.getSW() != ISO7816.SW_BYTES_REMAINING_00) {
                ne = getDataAPDU.getSW() - ISO7816.SW_BYTES_REMAINING_00;
            }

        } while (true);

        return responses.stream().reduce((a, b) -> {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy(a, 0, result, 0, a.length);
            System.arraycopy(b, 0, result, a.length, b.length);
            return result;
        }).get();
    }

    public byte[] sendGetData() {
        return sendGetData(256);
    }

    @After
    public void tearDown() {
        sim.resetRuntime();
    }

    @AfterClass
    public static void tearDownClass() {
    }
}
