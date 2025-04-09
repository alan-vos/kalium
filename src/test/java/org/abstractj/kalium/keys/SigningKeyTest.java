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

public class SigningKeyTest {

    @Test
    public void testGenerateSigninKey() {
        try {
            new SigningKey();
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testAcceptsRawValidKey() {
        try {
            byte[] rawKey = HEX.decode(SIGN_PRIVATE);
            new SigningKey(rawKey);
        } catch (Exception e) {
            fail("Should return a valid key size");
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testAcceptsHexValidKey() {
        try {
            new SigningKey(SIGN_PRIVATE, HEX);
        } catch (Exception e) {
            fail("Should return a valid key size");
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testCreateHexValidKey() {
        try {
            new SigningKey(SIGN_PRIVATE, HEX).toString();
        } catch (Exception e) {
            fail("Should return a valid key size");
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testCreateByteValidKey() {
        try {
            new SigningKey(SIGN_PRIVATE, HEX).toBytes();
        } catch (Exception e) {
            fail("Should return a valid key size");
            throw new RuntimeException(e);
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() {
        byte[] key = null;
        new SigningKey(key);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() {
        byte[] key = "short".getBytes();
        new SigningKey(key);
        fail("Should reject short keys");
    }

    @Test
    public void testSignMessageAsBytes() {
        byte[] rawKey = HEX.decode(SIGN_PRIVATE);
        byte[] signatureRaw = HEX.decode(SIGN_SIGNATURE);
        SigningKey key = new SigningKey(rawKey);
        byte[] signedMessage = key.sign(HEX.decode(SIGN_MESSAGE));
        assertArrayEquals("Message sign has failed", signatureRaw, signedMessage);
    }

    @Test
    public void testSignMessageAsHex() {
        SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
        String signature = key.sign(SIGN_MESSAGE, HEX);
        assertEquals("Message sign has failed", SIGN_SIGNATURE, signature);
    }

    @Test
    public void testSerializesToHex() {
        try {
            SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
            assertEquals("Correct sign key expected", SIGN_PRIVATE, key.toString());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testSerializesToBytes() {
        try {
            byte[] rawKey = HEX.decode(SIGN_PRIVATE);
            SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
            assertArrayEquals("Correct sign key expected", rawKey, key.toBytes());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testAccessVerifyKey() {
        SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
        VerifyKey v = key.getVerifyKey();
        assertEquals(SIGN_PUBLIC, v.toString());
    }

    @Test
    public void testRoundTrip() {
        SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
        String signature = key.sign(SIGN_MESSAGE, HEX);
        key.getVerifyKey().verify(SIGN_MESSAGE, signature, HEX);
    }
}
