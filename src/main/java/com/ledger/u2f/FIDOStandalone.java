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

import javacard.framework.JCSystem;
import javacard.security.RandomData;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class FIDOStandalone implements FIDOAPI {

    private KeyPair keyPair;
    private AESKey chipKey;
    private Cipher cipherEncrypt;
    private Cipher cipherDecrypt;
    private RandomData random;
    private byte[] scratch;

    private static final byte[] IV_ZERO_AES = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Init cipher engines and allocate memory.
     */
    public FIDOStandalone() {
        scratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        keyPair = new KeyPair(
        (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
        (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        Secp256r1.setCommonCurveParameters((ECKey) keyPair.getPrivate());
        Secp256r1.setCommonCurveParameters((ECKey) keyPair.getPublic());
        random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        // Initialize the unique wrapping key
        chipKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        random.nextBytes(scratch, (short) 0, (short) 32);
        chipKey.setKey(scratch, (short) 0);
        cipherEncrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherEncrypt.init(chipKey, Cipher.MODE_ENCRYPT, IV_ZERO_AES, (short) 0, (short) IV_ZERO_AES.length);
        cipherDecrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherDecrypt.init(chipKey, Cipher.MODE_DECRYPT, IV_ZERO_AES, (short) 0, (short) IV_ZERO_AES.length);
    }

    /**
     * Interleave two byte arrays into the target one, nibble by nibble.
     * Example:
     *  array1 =  [0x12, 0x34]
     *  array2 =  [0xab, 0xcd]
     *         -> [0x1a, 0x2b, 0x3c, 0x4d]
     * <p>
     * This is used to interleave the generated private key and the application parameter into two AES-CBC blocks,
     * as not doing so would result in the application parameter being encrypted as a block with an all zero IV which
     * would always result in the same first block for all generated private keys with the same application parameter
     * wrapped under the same wrapping key, which would break privacy of U2F.
     *
     * @param array1
     * @param array1Offset
     * @param array2
     * @param array2Offset
     * @param target
     * @param targetOffset
     * @param length 
     */
    private static void interleave(byte[] array1, short array1Offset, byte[] array2, short array2Offset, byte[] target, short targetOffset, short length) {
        for (short i = 0; i < length; i++) {
            short a = (short) (array1[(short) (array1Offset + i)] & 0xff);
            short b = (short) (array2[(short) (array2Offset + i)] & 0xff);
            target[(short) (targetOffset + 2 * i)] = (byte) ((short) (a & 0xf0) | (short) (b >> 4));
            target[(short) (targetOffset + 2 * i + 1)] = (byte) ((short) ((a & 0x0f) << 4) | (short) (b & 0x0f));
        }
    }

    /**
     * Deinterleave a byte array back into two arrays of half size.
     *  Example:
     *  src = [0x1a, 0x2b, 0x3c, 0x4d]
     *     -> [0x12, 0x34] and [0xab, 0xcd]
     *
     * @param src
     * @param srcOffset
     * @param array1
     * @param array1Offset
     * @param array2
     * @param array2Offset
     * @param length 
     */
    private static void deinterleave(byte[] src, short srcOffset, byte[] array1, short array1Offset, byte[] array2, short array2Offset, short length) {
        for (short i = 0; i < length; i++) {
            short a = (short) (src[(short) (srcOffset + 2 * i)] & 0xff);
            short b = (short) (src[(short) (srcOffset + 2 * i + 1)] & 0xff);
            array1[(short) (array1Offset + i)] = (byte) ((short) (a & 0xf0) | (short) (b >> 4));
            array2[(short) (array2Offset + i)] = (byte) (((short) (a & 0x0f) << 4) | (short) (b & 0x0f));
        }
    }

    /* @override */
    public short generateKeyAndWrap(byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey generatedPrivateKey, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset) {
        // Generate a new pair
        keyPair.genKeyPair();
        // Copy public key
        ((ECPublicKey) keyPair.getPublic()).getW(publicKey, publicKeyOffset);
        // Wrap keypair and application parameters
        ((ECPrivateKey) keyPair.getPrivate()).getS(scratch, (short) 0);
        interleave(applicationParameter, applicationParameterOffset, scratch, (short) 0, keyHandle, keyHandleOffset, (short) 32);
        cipherEncrypt.doFinal(keyHandle, keyHandleOffset, (short) 64, keyHandle, keyHandleOffset);
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 32, (byte) 0x00);
        return (short) 64;
    }

    /* @override */
    public boolean unwrap(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey unwrappedPrivateKey) {
        // Verify
        cipherDecrypt.doFinal(keyHandle, keyHandleOffset, (short) 64, keyHandle, keyHandleOffset);
        deinterleave(keyHandle, keyHandleOffset, scratch, (short) 0, scratch, (short) 32, (short) 32);
        if (!FIDOUtils.compareConstantTime(applicationParameter, applicationParameterOffset, scratch, (short) 0, (short) 32)) {
            Util.arrayFillNonAtomic(scratch, (short) 32, (short) 32, (byte) 0x00);
            Util.arrayFillNonAtomic(keyHandle, keyHandleOffset, (short) 64, (byte) 0x00);
            return false;
        }
        Util.arrayFillNonAtomic(keyHandle, keyHandleOffset, (short) 64, (byte) 0x00);
        if (unwrappedPrivateKey != null) {
            unwrappedPrivateKey.setS(scratch, (short) 32, (short) 32);
        }
        Util.arrayFillNonAtomic(scratch, (short) 32, (short) 32, (byte) 0x00);
        return true;
    }

}
