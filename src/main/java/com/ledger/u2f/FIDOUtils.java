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
import javacard.security.ECPublicKey;

public class FIDOUtils {

    public static boolean compareConstantTime(byte[] array1, short array1Offset, byte[] array2, short array2Offset, short length) {
        short givenLength = length;
        byte status = (byte)0;
        short counter = (short)0;

        if (length == 0) {
            return false;
        }
        while ((length--) != 0) {
            status |= (byte)((array1[(short)(array1Offset + length)]) ^ (array2[(short)(array2Offset + length)]));
            counter++;
        }
        if (counter != givenLength) {
            return false;
        }
        return (status == 0);
    }

}
