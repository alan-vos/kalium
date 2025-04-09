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

package org.abstractj.kalium.crypto;

import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SecretBoxTest {

    @Test
    public void testAcceptStrings() {
        try {
            new SecretBox(SECRET_KEY, HEX);
        } catch (Exception e) {
            fail("SecretBox should accept strings");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullKey() {
        byte[] key = null;
        new SecretBox(key);
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testShortKey() {
        final String key = "hello";
        new SecretBox(key.getBytes());
        fail("Should raise an exception");
    }

    @Test
    public void testEncrypt() {
        final SecretBox box = new SecretBox(SECRET_KEY, HEX);

        final byte[] nonce = HEX.decode(BOX_NONCE);
        final byte[] message = HEX.decode(BOX_MESSAGE);
        final byte[] ciphertext = HEX.decode(BOX_CIPHERTEXT);

        final byte[] result = box.encrypt(nonce, message);
        assertTrue("failed to generate ciphertext", Arrays.equals(result, ciphertext));
    }

    @Test
    public void testDecrypt() {

        final SecretBox box = new SecretBox(SECRET_KEY, HEX);

        final byte[] nonce = HEX.decode(BOX_NONCE);
        final byte[] expectedMessage = HEX.decode(BOX_MESSAGE);
        final byte[] ciphertext = box.encrypt(nonce, expectedMessage);

        final byte[] message = box.decrypt(nonce, ciphertext);

        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptCorruptedCipherText() {
        final SecretBox box = new SecretBox(SECRET_KEY, HEX);
        final byte[] nonce = HEX.decode(BOX_NONCE);
        final byte[] message = HEX.decode(BOX_MESSAGE);
        final byte[] ciphertext = box.encrypt(nonce, message);
        ciphertext[23] = ' ';

        box.decrypt(nonce, ciphertext);
        fail("Should raise an exception");
    }
}
