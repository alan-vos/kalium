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
import static org.junit.Assert.*;

public class HashTest {

    private final Hash hash = new Hash();

    @Test
    public void testSha256() {
        final byte[] rawMessage = SHA256_MESSAGE.getBytes();
        String result = HEX.encode(hash.sha256(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(SHA256_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testSha256EmptyString() {
        final byte[] result = hash.sha256("".getBytes());
        assertEquals("Hash is invalid", SHA256_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testSha256HexString() {
        final String result = hash.sha256(SHA256_MESSAGE, HEX);
        assertEquals("Hash is invalid", SHA256_DIGEST, result);
    }

    @Test
    public void testSha256EmptyHexString() {
        final String result = hash.sha256("", HEX);
        assertEquals("Hash is invalid", SHA256_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha256NullByte() {
        try {
            hash.sha256("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testSha512() {
        final byte[] rawMessage = SHA512_MESSAGE.getBytes();
        String result = HEX.encode(hash.sha512(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(SHA512_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testSha512EmptyString() {
        final byte[] result = hash.sha512("".getBytes());
        assertEquals("Hash is invalid", SHA512_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testSha512HexString() {
        final String result = hash.sha512(SHA512_MESSAGE, HEX);
        assertEquals("Hash is invalid", SHA512_DIGEST, result);
    }

    @Test
    public void testSha512EmptyHexString() {
        final String result = hash.sha512("", HEX);
        assertEquals("Hash is invalid", SHA512_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha512NullByte() {
        try {
            hash.sha512("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testBlake2() {
        final byte[] rawMessage = Blake2_MESSAGE.getBytes();
        String result = HEX.encode(hash.blake2(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(Blake2_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testBlake2EmptyString() {
        final byte[] result = hash.blake2("".getBytes());
        assertEquals("Hash is invalid", Blake2_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testBlake2HexString() {
        final String result = hash.blake2(Blake2_MESSAGE, HEX);
        assertEquals("Hash is invalid", Blake2_DIGEST, result);
    }

    @Test
    public void testBlake2EmptyHexString() {
        final String result = hash.blake2("", HEX);
        assertEquals("Hash is invalid", Blake2_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testBlake2NullByte() {
        try {
            hash.blake2("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testBlake2WithSaltAndPersonal() {
        final byte[] result = hash.blake2(Blake2_MESSAGE.getBytes(), Blake2_KEY.getBytes(),
                Blake2_SALT.getBytes(),
                Blake2_PERSONAL.getBytes());
        assertEquals("Hash is invalid", Blake2_DIGEST_WITH_SALT_PERSONAL, HEX.encode(result));
    }
}
