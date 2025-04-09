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
import static org.abstractj.kalium.fixture.TestVectors.BOB_PRIVATE_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PUBLIC_KEY;
import static org.junit.Assert.*;

public class KeyPairTest {

    @Test
    public void testGenerateKeyPair() {
        try {
            final KeyPair key = new KeyPair();
            assertNotNull(key.getPrivateKey());
            assertNotNull(key.getPublicKey());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testAcceptsValidKey() {
        try {
            final byte[] rawKey = HEX.decode(BOB_PRIVATE_KEY);
            new KeyPair(rawKey);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testAcceptsHexEncodedKey() {
        try {
            new KeyPair(BOB_PRIVATE_KEY, HEX);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() {
        final byte[] privateKey = null;
        new KeyPair(null);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() {
        final byte[] privateKey = "short".getBytes();
        new KeyPair(privateKey);
        fail("Should reject null keys");
    }

    @Test
    public void testGeneratePublicKey() {
        try {
            final byte[] pk = HEX.decode(BOB_PRIVATE_KEY);
            final KeyPair key = new KeyPair(pk);
            assertNotNull(key.getPublicKey());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testPrivateKeyToString() {
        try {
            KeyPair key = new KeyPair(BOB_PRIVATE_KEY, HEX);
            assertEquals("Correct private key expected", BOB_PRIVATE_KEY, key.getPrivateKey().toString());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testPrivateKeyToBytes() {
        try {
            final KeyPair key = new KeyPair(BOB_PRIVATE_KEY, HEX);
            assertArrayEquals("Correct private key expected", HEX.decode(BOB_PUBLIC_KEY), key.getPublicKey().toBytes());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testPublicKeyToString() {
        try {
            final KeyPair key = new KeyPair(BOB_PRIVATE_KEY, HEX);
            assertEquals("Correct public key expected", BOB_PUBLIC_KEY, key.getPublicKey().toString());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }


    /**
     * TODO: This unit test is a friendly reminder to be investigated
     *
     * @see <a href="https://github.com/abstractj/kalium/pull/9</a>
     */

    /*@Ignore
    @Test
    public void testPublicKeyShouldBeProperlyCalculated() {
        final KeyPair kp = new KeyPair();
        final KeyPair kp2 = new KeyPair(kp.getPrivateKey().toBytes());
        assertEquals("Private key should be the same", kp.getPrivateKey().toBytes(), kp2.getPrivateKey().toBytes());
        assertEquals("Public key should be the same", kp.getPublicKey().toBytes(), kp2.getPublicKey().toBytes());
    }*/

    @Test
    public void testPublicKeyToBytes() {
        try {
            final KeyPair key = new KeyPair(BOB_PRIVATE_KEY, HEX);
            assertArrayEquals("Correct public key expected", HEX.decode(BOB_PUBLIC_KEY), key.getPublicKey().toBytes());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }
}
