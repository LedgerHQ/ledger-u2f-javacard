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

import javacard.security.ECPrivateKey;

public interface FIDOAPI {
    /**
     * Generate a new key pair and wrap it.
     * @param applicationParameter
     * @param applicationParameterOffset
     * @param generatedPrivateKey not used
     * @param publicKey
     * @param publicKeyOffset
     * @param keyHandle output array
     * @param keyHandleOffset offset into output array
     * @return always 64
     */
    short generateKeyAndWrap(byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey generatedPrivateKey, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset);

    /**
     * Unwrap a previously wrapped key.
     * @param keyHandle
     * @param keyHandleOffset
     * @param keyHandleLength not used, assumed 64
     * @param applicationParameter application to compare with
     * @param applicationParameterOffset
     * @param unwrappedPrivateKey output variable
     * @return true if a valid key belonging to the indicated application is obtained
     */
    boolean unwrap(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey unwrappedPrivateKey);
}
