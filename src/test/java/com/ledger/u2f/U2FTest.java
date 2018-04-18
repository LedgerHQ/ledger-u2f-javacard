package com.ledger.u2f;


import apdu4j.ISO7816;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.Test;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class U2FTest extends SimulatorTestBase {
    private final static byte[] attestatioPrivkey = new byte[]{(byte) 0xf3, (byte) 0xfc, (byte) 0xcc, (byte) 0x0d, (byte) 0x00, (byte) 0xd8, (byte) 0x03, (byte) 0x19, (byte) 0x54, (byte) 0xf9, (byte) 0x08, (byte) 0x64, (byte) 0xd4, (byte) 0x3c, (byte) 0x24, (byte) 0x7f, (byte) 0x4b, (byte) 0xf5, (byte) 0xf0, (byte) 0x66, (byte) 0x5c, (byte) 0x6b, (byte) 0x50, (byte) 0xcc, (byte) 0x17, (byte) 0x74, (byte) 0x9a, (byte) 0x27, (byte) 0xd1, (byte) 0xcf, (byte) 0x76, (byte) 0x64};
    private final static byte[] attestationCert = new byte[]{(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x3c, (byte) 0x30, (byte) 0x81, (byte) 0xe4, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x0a, (byte) 0x47, (byte) 0x90, (byte) 0x12, (byte) 0x80, (byte) 0x00, (byte) 0x11, (byte) 0x55, (byte) 0x95, (byte) 0x73, (byte) 0x52, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x17, (byte) 0x31, (byte) 0x15, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x0c, (byte) 0x47, (byte) 0x6e, (byte) 0x75, (byte) 0x62, (byte) 0x62, (byte) 0x79, (byte) 0x20, (byte) 0x50, (byte) 0x69, (byte) 0x6c, (byte) 0x6f, (byte) 0x74, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x32, (byte) 0x30, (byte) 0x38, (byte) 0x31, (byte) 0x34, (byte) 0x31, (byte) 0x38, (byte) 0x32, (byte) 0x39, (byte) 0x33, (byte) 0x32, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x33, (byte) 0x30, (byte) 0x38, (byte) 0x31, (byte) 0x34, (byte) 0x31, (byte) 0x38, (byte) 0x32, (byte) 0x39, (byte) 0x33, (byte) 0x32, (byte) 0x5a, (byte) 0x30, (byte) 0x31, (byte) 0x31, (byte) 0x2f, (byte) 0x30, (byte) 0x2d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x26, (byte) 0x50, (byte) 0x69, (byte) 0x6c, (byte) 0x6f, (byte) 0x74, (byte) 0x47, (byte) 0x6e, (byte) 0x75, (byte) 0x62, (byte) 0x62, (byte) 0x79, (byte) 0x2d, (byte) 0x30, (byte) 0x2e, (byte) 0x34, (byte) 0x2e, (byte) 0x31, (byte) 0x2d, (byte) 0x34, (byte) 0x37, (byte) 0x39, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x38, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x31, (byte) 0x31, (byte) 0x35, (byte) 0x35, (byte) 0x39, (byte) 0x35, (byte) 0x37, (byte) 0x33, (byte) 0x35, (byte) 0x32, (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0x8d, (byte) 0x61, (byte) 0x7e, (byte) 0x65, (byte) 0xc9, (byte) 0x50, (byte) 0x8e, (byte) 0x64, (byte) 0xbc, (byte) 0xc5, (byte) 0x67, (byte) 0x3a, (byte) 0xc8, (byte) 0x2a, (byte) 0x67, (byte) 0x99, (byte) 0xda, (byte) 0x3c, (byte) 0x14, (byte) 0x46, (byte) 0x68, (byte) 0x2c, (byte) 0x25, (byte) 0x8c, (byte) 0x46, (byte) 0x3f, (byte) 0xff, (byte) 0xdf, (byte) 0x58, (byte) 0xdf, (byte) 0xd2, (byte) 0xfa, (byte) 0x3e, (byte) 0x6c, (byte) 0x37, (byte) 0x8b, (byte) 0x53, (byte) 0xd7, (byte) 0x95, (byte) 0xc4, (byte) 0xa4, (byte) 0xdf, (byte) 0xfb, (byte) 0x41, (byte) 0x99, (byte) 0xed, (byte) 0xd7, (byte) 0x86, (byte) 0x2f, (byte) 0x23, (byte) 0xab, (byte) 0xaf, (byte) 0x02, (byte) 0x03, (byte) 0xb4, (byte) 0xb8, (byte) 0x91, (byte) 0x1b, (byte) 0xa0, (byte) 0x56, (byte) 0x99, (byte) 0x94, (byte) 0xe1, (byte) 0x01, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x47, (byte) 0x00, (byte) 0x30, (byte) 0x44, (byte) 0x02, (byte) 0x20, (byte) 0x60, (byte) 0xcd, (byte) 0xb6, (byte) 0x06, (byte) 0x1e, (byte) 0x9c, (byte) 0x22, (byte) 0x26, (byte) 0x2d, (byte) 0x1a, (byte) 0xac, (byte) 0x1d, (byte) 0x96, (byte) 0xd8, (byte) 0xc7, (byte) 0x08, (byte) 0x29, (byte) 0xb2, (byte) 0x36, (byte) 0x65, (byte) 0x31, (byte) 0xdd, (byte) 0xa2, (byte) 0x68, (byte) 0x83, (byte) 0x2c, (byte) 0xb8, (byte) 0x36, (byte) 0xbc, (byte) 0xd3, (byte) 0x0d, (byte) 0xfa, (byte) 0x02, (byte) 0x20, (byte) 0x63, (byte) 0x1b, (byte) 0x14, (byte) 0x59, (byte) 0xf0, (byte) 0x9e, (byte) 0x63, (byte) 0x30, (byte) 0x05, (byte) 0x57, (byte) 0x22, (byte) 0xc8, (byte) 0xd8, (byte) 0x9b, (byte) 0x7f, (byte) 0x48, (byte) 0x88, (byte) 0x3b, (byte) 0x90, (byte) 0x89, (byte) 0xb8, (byte) 0x8d, (byte) 0x60, (byte) 0xd1, (byte) 0xd9, (byte) 0x79, (byte) 0x59, (byte) 0x02, (byte) 0xb3, (byte) 0x04, (byte) 0x10, (byte) 0xdf};
    private final static byte[] challenge = new byte[]{(byte) 0x41, (byte) 0x42, (byte) 0xd2, (byte) 0x1c, (byte) 0x00, (byte) 0xd9, (byte) 0x4f, (byte) 0xfb, (byte) 0x9d, (byte) 0x50, (byte) 0x4a, (byte) 0xda, (byte) 0x8f, (byte) 0x99, (byte) 0xb7, (byte) 0x21, (byte) 0xf4, (byte) 0xb1, (byte) 0x91, (byte) 0xae, (byte) 0x4e, (byte) 0x37, (byte) 0xca, (byte) 0x01, (byte) 0x40, (byte) 0xf6, (byte) 0x96, (byte) 0xb6, (byte) 0x98, (byte) 0x3c, (byte) 0xfa, (byte) 0xcb};
    private final static byte[] application = new byte[]{(byte) 0xf0, (byte) 0xe6, (byte) 0xa6, (byte) 0xa9, (byte) 0x70, (byte) 0x42, (byte) 0xa4, (byte) 0xf1, (byte) 0xf1, (byte) 0xc8, (byte) 0x7f, (byte) 0x5f, (byte) 0x7d, (byte) 0x44, (byte) 0x31, (byte) 0x5b, (byte) 0x2d, (byte) 0x85, (byte) 0x2c, (byte) 0x2d, (byte) 0xf5, (byte) 0xc7, (byte) 0x99, (byte) 0x1c, (byte) 0xc6, (byte) 0x62, (byte) 0x41, (byte) 0xbf, (byte) 0x70, (byte) 0x72, (byte) 0xd1, (byte) 0xc4};

    private final static byte[] U2F_VERSION_RESP = {'U', '2', 'F', '_', 'V', '2', (byte) 0x90, 0x00};

    private static ECParameterSpec p256;

    static {
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        p256 = new ECNamedCurveSpec("P-256", curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    }


    @Test
    public void testAttestationCertNotSet() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);
        int[] fidoINS = {0x01, 0x02, 0x03};
        for (int ins : fidoINS) {
            CommandAPDU apdu = new CommandAPDU(0x00, ins, 0, 0);
            ResponseAPDU resp = sim.transmitCommand(apdu);
            assertThat(resp.getSW(), is(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED));
        }
    }

    @Test
    public void testSetAttestationCert() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        CommandAPDU certApdu = new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert);
        ResponseAPDU certResponse = sim.transmitCommand(certApdu);
        assertThat(certResponse.getSW(), is(ISO7816.SW_NO_ERROR));
    }

    @Test
    public void testSetAttestationCertAgain() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        CommandAPDU certApdu = new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert);
        sim.transmitCommand(certApdu);

        ResponseAPDU certResponse = sim.transmitCommand(certApdu);
        assertThat(certResponse.getSW(), is(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED));
    }

    @Test
    public void testSelectGivesVersion() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));

        byte[] response = sim.selectAppletWithResult(aid);
        assertThat(response, is(U2F_VERSION_RESP));
    }

    @Test
    public void testGetVersion() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));

        ResponseAPDU versionAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0x03, 0, 0));
        assertThat(versionAPDU.getBytes(), is(U2F_VERSION_RESP));
    }

    @Test
    public void testEnroll() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, InvalidKeySpecException {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));
        byte[] enrollData = new byte[64];
        System.arraycopy(challenge, 0, enrollData, 0, 32);
        System.arraycopy(application, 0, enrollData, 32, 32);

        ResponseAPDU responseAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0x01, 0, 0, enrollData, 65535));
        assertThat(responseAPDU.getSW(), is(ISO7816.SW_NO_ERROR));

        byte[] responseData = responseAPDU.getData();
        assertThat(responseData[0], is((byte) 0x05));

        byte[] pubKey = new byte[65];
        System.arraycopy(responseData, 1, pubKey, 0, 65);

        ECPublicKeySpec ecPubKeySpec = new ECPublicKeySpec(ECPointUtil.decodePoint(p256.getCurve(), pubKey), p256);
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC");
        ecKeyFactory.generatePublic(ecPubKeySpec);

        byte keyHandleLength = responseData[66];
        byte[] keyHandle = new byte[keyHandleLength];
        System.arraycopy(responseData, 67, keyHandle, 0, keyHandleLength);

        ByteArrayInputStream certStream = new ByteArrayInputStream(responseData, 67 + keyHandleLength, responseData.length - (67 + keyHandleLength));
        X509Certificate cert = X509Certificate.getInstance(certStream);
        assertThat(cert.getSubjectDN().toString(), is("CN=PilotGnubby-0.4.1-47901280001155957352"));
        assertThat(cert.getIssuerDN().toString(), is("CN=Gnubby Pilot"));
        assertThat(cert.getVersion(), is(2));

        int sigLength = certStream.available();
        byte[] signature = new byte[sigLength];
        System.arraycopy(responseData, responseData.length - sigLength, signature, 0, sigLength);

        Signature verifier = Signature.getInstance(cert.getSigAlgName());
        verifier.initVerify(cert.getPublicKey());

        byte[] clientData = new byte[65 + keyHandleLength + 65];
        clientData[0] = 0;
        System.arraycopy(application, 0, clientData, 1, 32);
        System.arraycopy(challenge, 0, clientData, 33, 32);
        System.arraycopy(keyHandle, 0, clientData, 65, keyHandleLength);
        System.arraycopy(pubKey, 0, clientData, 65 + keyHandleLength, 65);

        verifier.update(clientData);

        assertThat(verifier.verify(signature), is(true));
    }

    @Test
    public void testEnrollGetData() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, InvalidKeyException, SignatureException {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));
        byte[] enrollData = new byte[64];
        System.arraycopy(challenge, 0, enrollData, 0, 32);
        System.arraycopy(application, 0, enrollData, 32, 32);

        ResponseAPDU responseAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0x01, 0, 0, enrollData));
        assertThat(responseAPDU.getSW(), is(ISO7816.SW_BYTES_REMAINING_00));

        List<byte[]> responses = new LinkedList<>();
        int ne = 256;
        do {
            ResponseAPDU getDataAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0xC0, 0, 0, ne));
            responses.add(getDataAPDU.getData());
            int nr = getDataAPDU.getNr();

            assertThat(nr, lessThanOrEqualTo(256));
            if (ne == 256) {
                assertThat(getDataAPDU.getSW(), allOf(greaterThanOrEqualTo(ISO7816.SW_BYTES_REMAINING_00), lessThanOrEqualTo(ISO7816.SW_BYTES_REMAINING_00 + 256)));
            } else {
                assertThat(getDataAPDU.getSW(), is(ISO7816.SW_NO_ERROR));
                break;
            }

            if (getDataAPDU.getSW() != ISO7816.SW_BYTES_REMAINING_00) {
                ne = getDataAPDU.getSW() - ISO7816.SW_BYTES_REMAINING_00;
            }

        } while (true);

        byte[] responseData = responses.stream().reduce((a, b) -> {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy(a, 0, result, 0, a.length);
            System.arraycopy(b, 0, result, a.length, b.length);
            return result;
        }).get();

        byte[] pubKey = new byte[65];
        System.arraycopy(responseData, 1, pubKey, 0, 65);

        ECPublicKeySpec ecPubKeySpec = new ECPublicKeySpec(ECPointUtil.decodePoint(p256.getCurve(), pubKey), p256);
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC");
        ecKeyFactory.generatePublic(ecPubKeySpec);

        byte keyHandleLength = responseData[66];
        byte[] keyHandle = new byte[keyHandleLength];
        System.arraycopy(responseData, 67, keyHandle, 0, keyHandleLength);

        ByteArrayInputStream certStream = new ByteArrayInputStream(responseData, 67 + keyHandleLength, responseData.length - (67 + keyHandleLength));
        X509Certificate cert = X509Certificate.getInstance(certStream);
        assertThat(cert.getSubjectDN().toString(), is("CN=PilotGnubby-0.4.1-47901280001155957352"));
        assertThat(cert.getIssuerDN().toString(), is("CN=Gnubby Pilot"));
        assertThat(cert.getVersion(), is(2));

        int sigLength = certStream.available();
        byte[] signature = new byte[sigLength];
        System.arraycopy(responseData, responseData.length - sigLength, signature, 0, sigLength);

        Signature verifier = Signature.getInstance(cert.getSigAlgName());
        verifier.initVerify(cert.getPublicKey());

        byte[] clientData = new byte[65 + keyHandleLength + 65];
        clientData[0] = 0;
        System.arraycopy(application, 0, clientData, 1, 32);
        System.arraycopy(challenge, 0, clientData, 33, 32);
        System.arraycopy(keyHandle, 0, clientData, 65, keyHandleLength);
        System.arraycopy(pubKey, 0, clientData, 65 + keyHandleLength, 65);

        verifier.update(clientData);

        assertThat(verifier.verify(signature), is(true));
    }

    @Test
    public void testSignNotEnrolled() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));

        byte[] keyHandle = new byte[32];
        new Random().nextBytes(keyHandle);

        byte[] signData = new byte[97];
        System.arraycopy(challenge, 0, signData, 0, 32);
        System.arraycopy(application, 0, signData, 32, 32);
        signData[64] = 32;
        System.arraycopy(keyHandle, 0, signData, 65, 32);

        ResponseAPDU responseAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0x02, 0x03, 0, signData, 65535));
        assertThat(responseAPDU.getSW(), is(not(ISO7816.SW_NO_ERROR)));
    }

    @Test
    public void testEnrollAndSign() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));
        byte[] enrollData = new byte[64];
        System.arraycopy(challenge, 0, enrollData, 0, 32);
        System.arraycopy(application, 0, enrollData, 32, 32);

        ResponseAPDU enrollResponse = sim.transmitCommand(new CommandAPDU(0x00, 0x01, 0, 0, enrollData, 65535));
        byte[] responseData = enrollResponse.getData();

        sim.reset();
        sim.selectApplet(aid);

        byte keyHandleLength = responseData[66];
        byte[] keyHandle = new byte[keyHandleLength];
        System.arraycopy(responseData, 67, keyHandle, 0, keyHandleLength);

        byte[] signData = new byte[65 + keyHandleLength];
        System.arraycopy(challenge, 0, signData, 0, 32);
        System.arraycopy(application, 0, signData, 32, 32);
        signData[64] = keyHandleLength;
        System.arraycopy(keyHandle, 0, signData, 65, keyHandleLength);

        ResponseAPDU signResponse = sim.transmitCommand(new CommandAPDU(0x00, 0x02, 0x03, 0, signData, 65535));
        assertThat(signResponse.getSW(), is(ISO7816.SW_NO_ERROR));
    }

    @Test
    public void testGetDataNoData() {
        prepareApplet((byte) 0, attestationCert.length, attestatioPrivkey);

        sim.transmitCommand(new CommandAPDU(0xF0, 0x01, 0, 0, attestationCert));
        ResponseAPDU getDataAPDU = sim.transmitCommand(new CommandAPDU(0x00, 0xC0, 0, 0));
        assertThat(getDataAPDU.getSW(), is(ISO7816.SW_CONDITIONS_OF_USE_NOT_SATISFIED));
    }
    
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
