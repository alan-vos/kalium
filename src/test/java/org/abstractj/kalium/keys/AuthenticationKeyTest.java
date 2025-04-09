/**
 * Copyright 2015 Cisco Systems, Inc.
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

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_AUTH_HMACSHA512256_KEYBYTES;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class AuthenticationKeyTest {

    @Test
    public void testAcceptsValidKey() {
        try {
            byte[] rawKey = HEX.decode(AUTH_KEY);
            new AuthenticationKey(rawKey);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testAcceptsHexEncodedKey() {
        try {
            new AuthenticationKey(AUTH_KEY, HEX);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() {
        final byte[] key = null;
        new AuthenticationKey(key);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() {
        final byte[] key = "short".getBytes();
        new AuthenticationKey(key);
        fail("Should reject short keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectLongKey() {
        byte[] key = new byte[CRYPTO_AUTH_HMACSHA512256_KEYBYTES + 1];
        new AuthenticationKey(key);
        fail("Should reject long keys");
    }

    @Test
    public void testSerializesToHex() {
        try {
            AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
            assertEquals("Correct auth key expected", AUTH_KEY, key.toString());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testSerializesToBytes() {
        try {
            AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
            assertArrayEquals("Correct auth key expected", HEX.decode(AUTH_KEY), key.toBytes());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testSignMessageAsBytes() {
        final byte[] rawKey = HEX.decode(AUTH_KEY);
        final AuthenticationKey key = new AuthenticationKey(rawKey);
        final byte[] mac = key.sign(HEX.decode(AUTH_MESSAGE));
        assertTrue("Message sign has failed", Arrays.equals(HEX.decode(AUTH_HMAC_SHA512256), mac));
    }

    @Test
    public void testSignMessageAsHex() {
        AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
        String mac = key.sign(AUTH_MESSAGE, HEX);
        assertEquals("Message sign has failed", AUTH_HMAC_SHA512256, mac);
    }

    @Test
    public void testVerifyCorrectRawSignature() {
        byte[] rawSignature = HEX.decode(AUTH_HMAC_SHA512256);
        byte[] rawMessage = HEX.decode(AUTH_MESSAGE);
        byte[] rawKey = HEX.decode(AUTH_KEY);
        AuthenticationKey authKey = new AuthenticationKey(rawKey);
        assertTrue(authKey.verify(rawMessage, rawSignature));
    }

    @Test
    public void testVerifyCorrectHexSignature() {
        AuthenticationKey authKey = new AuthenticationKey(AUTH_KEY, HEX);
        assertTrue(authKey.verify(AUTH_MESSAGE, AUTH_HMAC_SHA512256, HEX));
    }

    @Test
    public void testDetectBadSignature() {
        try {
            byte[] rawSignature = HEX.decode(AUTH_HMAC_SHA512256);
            byte[] rawMessage = HEX.decode(AUTH_MESSAGE);
            byte[] rawKey = HEX.decode(AUTH_KEY);
            AuthenticationKey authKey = new AuthenticationKey(rawKey);
            rawMessage[0] += 1;
            authKey.verify(rawMessage, rawSignature);
            fail("Should an exception on bad signatures");
        } catch (Exception e) {
            assertTrue(true);
        }
    }

}
