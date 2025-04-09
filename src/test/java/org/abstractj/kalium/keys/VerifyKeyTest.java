/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.keys;

import org.junit.Test;

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.*;

public class VerifyKeyTest {

    @Test
    public void testVerifyCorrectRawSignature() {
        final byte[] rawSignature = HEX.decode(SIGN_SIGNATURE);
        final byte[] rawMessage = HEX.decode(SIGN_MESSAGE);
        final byte[] rawPublicKey = HEX.decode(SIGN_PUBLIC);
        final VerifyKey verifyKey = new VerifyKey(rawPublicKey);
        assertTrue(verifyKey.verify(rawMessage, rawSignature));
    }

    @Test
    public void testVerifyCorrectHexSignature() {
        final byte[] rawPublicKey = HEX.decode(SIGN_PUBLIC);
        final VerifyKey verifyKey = new VerifyKey(rawPublicKey);
        verifyKey.verify(SIGN_MESSAGE, SIGN_SIGNATURE, HEX);
        assertTrue(verifyKey.verify(SIGN_MESSAGE, SIGN_SIGNATURE, HEX));
    }

    @Test
    public void testDetectBadSignature() {
        try {
            final String badSignature = SIGN_SIGNATURE.concat("0000");
            final VerifyKey verifyKey = new VerifyKey(SIGN_PUBLIC, HEX);
            verifyKey.verify(SIGN_MESSAGE, badSignature, HEX);
            fail("Should an exception on bad signatures");
        } catch (Exception e) {
            assertTrue(true);
        }
    }

    @Test
    public void testSerializeToBytes() {
        final byte[] rawPublic = HEX.decode(SIGN_PUBLIC);
        final VerifyKey verifyKey = new VerifyKey(SIGN_PUBLIC, HEX);
        verifyKey.verify(SIGN_MESSAGE, SIGN_SIGNATURE, HEX);
        assertArrayEquals(verifyKey.toBytes(), rawPublic);
    }

    @Test
    public void testSerializeToString() {
        final VerifyKey verifyKey = new VerifyKey(SIGN_PUBLIC, HEX);
        verifyKey.verify(SIGN_MESSAGE, SIGN_SIGNATURE, HEX);
        assertEquals(SIGN_PUBLIC, verifyKey.toString());
    }

    @Test
    public void testInitializeFromHex() {
        final VerifyKey verifyKey = new VerifyKey(SIGN_PUBLIC, HEX);
        assertTrue(verifyKey.verify(SIGN_MESSAGE, SIGN_SIGNATURE, HEX));
    }

}
