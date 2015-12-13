/*
*******************************************************************************
*   FIDO U2F Authenticator
*   (c) 2015 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package com.ledger.u2f;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import javacard.security.KeyBuilder;
import javacardx.apdu.ExtendedLength;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacard.security.CryptoException;

public class U2FApplet extends Applet implements ExtendedLength {

    private static byte flags;
    private static byte[] counter;
    private static byte[] scratchPersistent;
    private static byte[] scratch;
    private static byte[] attestationCertificate;
    private static boolean attestationCertificateSet;
    private static ECPrivateKey attestationPrivateKey;
    private static ECPrivateKey localPrivateKey;
    private static boolean localPrivateTransient;
    private static boolean counterOverflowed;
    private static Signature attestationSignature;
    private static Signature localSignature;
    private static FIDOAPI fidoImpl;

    private static final byte VERSION[] = { 'U', '2', 'F', '_', 'V', '2' };

    private static final byte FIDO_CLA = (byte)0x00;
    private static final byte FIDO_INS_ENROLL = (byte)0x01;
    private static final byte FIDO_INS_SIGN = (byte)0x02;
    private static final byte FIDO_INS_VERSION = (byte)0x03;
    private static final byte ISO_INS_GET_DATA = (byte)0xC0;

    private static final byte PROPRIETARY_CLA = (byte)0xF0;
    private static final byte FIDO_ADM_SET_ATTESTATION_CERT = (byte)0x01;

    private static final byte SCRATCH_TRANSPORT_STATE = (byte)0;
    private static final byte SCRATCH_REMAINING_OFFSET = (byte)1;
    private static final byte SCRATCH_PAD = (byte)3;
    private static final short SCRATCH_PAD_SIZE = (short)75;

    private static final byte TRANSPORT_EXTENDED = (byte)1;
    private static final byte TRANSPORT_NOT_EXTENDED = (byte)2;

    private static final byte P1_SIGN_OPERATION = (byte)0x03;
    private static final byte P1_SIGN_CHECK_ONLY = (byte)0x07;

    private static final byte ENROLL_LEGACY_VERSION = (byte)0x05;
    private static final byte RFU_ENROLL_SIGNED_VERSION[] = { (byte)0x00 };

    private static final short ENROLL_PUBLIC_KEY_OFFSET = (short)1;
    private static final short ENROLL_KEY_HANDLE_LENGTH_OFFSET = (short)66;
    private static final short ENROLL_KEY_HANDLE_OFFSET = (short)67;
    private static final short SCRATCH_CHALLENGE_OFFSET = (short)(SCRATCH_PAD + 0);
    private static final short SCRATCH_APPLICATION_PARAMETER_OFFSET = (short)(SCRATCH_CHALLENGE_OFFSET + 32);

    private static final byte FLAG_USER_PRESENCE_VERIFIED = (byte)0x01;

    private static final short FIDO_SW_TEST_OF_PRESENCE_REQUIRED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short FIDO_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;

    private static final byte INSTALL_FLAG_DISABLE_USER_PRESENCE = (byte)0x01;

    // Parameters
    // 1 byte : flags
    // 2 bytes big endian short : length of attestation certificate
    // 32 bytes : private attestation key
    public U2FApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        if (parametersLength != 35) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        counter = new byte[4];
        scratchPersistent = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);
        scratch = JCSystem.makeTransientByteArray((short)(SCRATCH_PAD + SCRATCH_PAD_SIZE), JCSystem.CLEAR_ON_DESELECT);
        try {
            // ok, let's save RAM
            localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
            localPrivateTransient = true;
        }
        catch(CryptoException e) {
            try {
                // ok, let's save a bit less RAM
                localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
                localPrivateTransient = true;
            }
            catch(CryptoException e1) {
                // ok, let's test the flash wear leveling \o/
                localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
                Secp256r1.setCommonCurveParameters(localPrivateKey);
            }
        }
        attestationSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        localSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        flags = parameters[parametersOffset];
        attestationCertificate = new byte[Util.getShort(parameters, (short)(parametersOffset + 1))];
        attestationPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256r1.setCommonCurveParameters(attestationPrivateKey);
        attestationPrivateKey.setS(parameters, (short)(parametersOffset + 3), (short)32);
        attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);
        fidoImpl = new FIDOStandalone();
    }

    private void handleSetAttestationCert(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        short copyOffset = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
        if ((short)(copyOffset + len) > (short)attestationCertificate.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopy(buffer, dataOffset, attestationCertificate, copyOffset, len);
        if ((short)(copyOffset + len) == (short)attestationCertificate.length) {
            attestationCertificateSet = true;
        }
    }

    private void handleEnroll(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);
        short outOffset;
        if (len != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Deny if user presence cannot be validated
        if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            if (scratchPersistent[0] != 0) {
                ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
            }
        }
        // Check if the counter overflowed
        if (counterOverflowed) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        // Set user presence
        scratchPersistent[0] = (byte)1;
        Util.arrayCopyNonAtomic(buffer, dataOffset, scratch, SCRATCH_PAD, (short)64);
        // Generate the key pair
        if (localPrivateTransient) {
            Secp256r1.setCommonCurveParameters(localPrivateKey);
        }
        short keyHandleLength = fidoImpl.generateKeyAndWrap(scratch, SCRATCH_APPLICATION_PARAMETER_OFFSET, localPrivateKey, buffer, ENROLL_PUBLIC_KEY_OFFSET, buffer, ENROLL_KEY_HANDLE_OFFSET);
        buffer[0] = ENROLL_LEGACY_VERSION;
        buffer[ENROLL_KEY_HANDLE_LENGTH_OFFSET] = (byte)keyHandleLength;
        // Prepare the attestation
        attestationSignature.update(RFU_ENROLL_SIGNED_VERSION, (short)0, (short)1);
        attestationSignature.update(scratch, SCRATCH_APPLICATION_PARAMETER_OFFSET, (short)32);
        attestationSignature.update(scratch, SCRATCH_CHALLENGE_OFFSET, (short)32);
        attestationSignature.update(buffer, ENROLL_KEY_HANDLE_OFFSET, keyHandleLength);
        attestationSignature.update(buffer, ENROLL_PUBLIC_KEY_OFFSET, (short)65);
        outOffset = (short)(ENROLL_PUBLIC_KEY_OFFSET + 65 + 1 + keyHandleLength);
        if (extendedLength) {
            // If using extended length, the message can be completed and sent immediately
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            Util.arrayCopyNonAtomic(attestationCertificate, (short)0, buffer, outOffset, (short)attestationCertificate.length);
            outOffset += (short)attestationCertificate.length;
            short signatureSize = attestationSignature.sign(buffer, (short)0, (short)0, buffer, outOffset);
            outOffset += signatureSize;
            apdu.setOutgoingAndSend((short)0, outOffset);
        }
        else {
            // Otherwise, keep the siganture and prepare a buffer with the beginning of the certificate
            short signatureSize = attestationSignature.sign(buffer, (short)0, (short)0, scratch, SCRATCH_PAD);
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            short partSize = (short)(256 - outOffset);
            Util.setShort(scratch, SCRATCH_REMAINING_OFFSET, partSize);
            Util.arrayCopyNonAtomic(attestationCertificate, (short)0, buffer, outOffset, partSize);
            // We safely assume that more than 256 bytes remain
            apdu.setOutgoingAndSend((short)0, (short)256);
            ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
        }
    }

    private void handleSign(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        boolean sign = false;
        boolean counterOverflow = true;
        short keyHandleLength;
        short outOffset = (short)0;
        if (len < 65) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        switch(p1) {
        case P1_SIGN_OPERATION:
            sign = true;
            break;
        case P1_SIGN_CHECK_ONLY:
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Check if the counter overflowed
        if (counterOverflowed) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        Util.arrayCopyNonAtomic(buffer, dataOffset, scratch, SCRATCH_PAD, (short)64);
        // Verify key handle
        if (localPrivateTransient) {
            Secp256r1.setCommonCurveParameters(localPrivateKey);
        }
        keyHandleLength = (short)(buffer[(short)(dataOffset + 64)] & 0xff);
        if (!fidoImpl.unwrap(buffer, (short)(dataOffset + 65), keyHandleLength, scratch, SCRATCH_APPLICATION_PARAMETER_OFFSET, (sign ? localPrivateKey : null))) {
            ISOException.throwIt(FIDO_SW_INVALID_KEY_HANDLE);
        }
        // If not signing, return with the "correct" exception
        if (!sign) {
            ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
        }
        // If signing, only proceed if user presence can be validated
        if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            if (scratchPersistent[0] != 0) {
                ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
            }
        }
        scratchPersistent[0] = (byte)1;
        // Increase the counter
        boolean carry = false;
        JCSystem.beginTransaction();
        for (byte i=0; i<4; i++) {
            short addValue = (i == 0 ? (short)1 : (short)0);
            short val = (short)((short)(counter[(short)(4 - 1 - i)] & 0xff) + addValue);
            if (carry) {
                val++;
            }
            carry = (val > 255);
            counter[(short)(4 - 1 - i)] = (byte)val;
        }
        JCSystem.commitTransaction();
        if (carry) {
            // Game over
            counterOverflowed = true;
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        // Prepare reply
        buffer[outOffset++] = FLAG_USER_PRESENCE_VERIFIED;
        outOffset = Util.arrayCopyNonAtomic(counter, (short)0, buffer, outOffset, (short)4);
        localSignature.init(localPrivateKey, Signature.MODE_SIGN);
        localSignature.update(scratch, SCRATCH_APPLICATION_PARAMETER_OFFSET, (short)32);
        localSignature.update(buffer, (short)0, (short)5);
        outOffset += localSignature.sign(scratch, SCRATCH_CHALLENGE_OFFSET, (short)32, buffer, outOffset);
        apdu.setOutgoingAndSend((short)0, outOffset);
    }

    private void handleVersion(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
        apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
    }

    private void handleGetData(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short length = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
        short currentOffset = Util.getShort(scratch, SCRATCH_REMAINING_OFFSET);
        short outOffset = (short)0;
        short signatureSize = (short)(2 + (scratch[(short)(SCRATCH_PAD + 1)] & 0xff));
        short totalSize = (short)((short)attestationCertificate.length + signatureSize);
        if ((scratch[SCRATCH_TRANSPORT_STATE] != TRANSPORT_NOT_EXTENDED) || (currentOffset >= totalSize)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (currentOffset < (short)attestationCertificate.length) {
            short remainingAttestation = (short)(attestationCertificate.length - currentOffset);
            short blockSize = (remainingAttestation < 256 ? remainingAttestation : 256);
            Util.arrayCopyNonAtomic(attestationCertificate, currentOffset, buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
        }
        if (currentOffset >= (short)(attestationCertificate.length)) {
            short signatureOffset = (short)(currentOffset - (short)attestationCertificate.length);
            short remainingSignature = (short)(signatureSize - (currentOffset - (short)attestationCertificate.length));
            short remainingBlock = (short)(256 - outOffset);
            if (remainingBlock > remainingSignature) {
                remainingBlock = remainingSignature;
            }
            Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_PAD + signatureOffset), buffer, outOffset, remainingBlock);
            outOffset += remainingBlock;
            currentOffset += remainingBlock;
        }
        Util.setShort(scratch, SCRATCH_REMAINING_OFFSET, currentOffset);
        apdu.setOutgoingAndSend((short)0, outOffset);
        if ((short)(totalSize - currentOffset) > 256) {
            ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
        }
        else if ((short)(totalSize - currentOffset) != 0) {
            ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + totalSize - currentOffset));
        }
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            if (attestationCertificateSet) {
                Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
                apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
            }
            return;
        }
        if (buffer[ISO7816.OFFSET_CLA] == PROPRIETARY_CLA) {
            if (attestationCertificateSet) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            switch(buffer[ISO7816.OFFSET_INS]) {
            case FIDO_ADM_SET_ATTESTATION_CERT:
                handleSetAttestationCert(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else if (buffer[ISO7816.OFFSET_CLA] == FIDO_CLA) {
            if (!attestationCertificateSet) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            switch(buffer[ISO7816.OFFSET_INS]) {
            case FIDO_INS_ENROLL:
                handleEnroll(apdu);
                break;
            case FIDO_INS_SIGN:
                handleSign(apdu);
                break;
            case FIDO_INS_VERSION:
                handleVersion(apdu);
                break;
            case ISO_INS_GET_DATA:
                handleGetData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short)(bArray[offset] + 1); // instance
        offset += (short)(bArray[offset] + 1); // privileges
        new U2FApplet(bArray, (short)(offset + 1), bArray[offset]).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
}

