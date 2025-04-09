/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AdvancedTest {

    @Test
    public void testXsalsa20HappyFlow() {
        final Random random = new Random();
        final Advanced advanced = new Advanced();
        final byte[] nonce = random.randomBytes(24);
        final byte[] key = random.randomBytes(32);
        final String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        final byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, nonce, key); // decrypt
        assertEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectNonce() {
        final Random random = new Random();
        final Advanced advanced = new Advanced();
        final byte[] nonce = random.randomBytes(24);
        final byte[] incorrectNonce = random.randomBytes(24);
        final byte[] key = random.randomBytes(32);
        final String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        final byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, incorrectNonce, key); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectKey() {
        final Random random = new Random();
        final Advanced advanced = new Advanced();
        final byte[] nonce = random.randomBytes(24);
        final byte[] key = random.randomBytes(32);
        final byte[] incorrectKey = random.randomBytes(32);
        final String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        final byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, nonce, incorrectKey); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectKeyAndIncorrectNonce() {
        final Random random = new Random();
        Advanced advanced = new Advanced();
        byte[] nonce = random.randomBytes(24);
        byte[] incorrectNonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        byte[] incorrectKey = random.randomBytes(32);
        String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, incorrectNonce, incorrectKey); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

}
