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

import jnr.ffi.annotations.IgnoreError;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;

public class Hash {

    @IgnoreError
    public byte[] sha256(final byte[] message) {
        final byte[] buffer = new byte[CRYPTO_HASH_SHA256_BYTES];
        sodium().crypto_hash_sha256(buffer, message, message.length);
        return buffer;
    }

    @IgnoreError
    public byte[] sha512(final byte[] message) {
        final byte[] buffer = new byte[CRYPTO_HASH_SHA512_BYTES];
        sodium().crypto_hash_sha512(buffer, message, message.length);
        return buffer;
    }

    @IgnoreError
    public String sha256(final String message,
                         final Encoder encoder) {
        final byte[] hash = sha256(message.getBytes());
        return encoder.encode(hash);
    }

    @IgnoreError
    public String sha512(final String message,
                         final Encoder encoder) {
        final byte[] hash = sha512(message.getBytes());
        return encoder.encode(hash);
    }

    @IgnoreError
    public byte[] blake2(final byte[] message) throws UnsupportedOperationException {
        final byte[] buffer = new byte[CRYPTO_GENERICHASH_BLAKE2B_BYTES];
        sodium().crypto_generichash_blake2b(buffer, CRYPTO_GENERICHASH_BLAKE2B_BYTES, message, message.length, null, 0);
        return buffer;
    }

    @IgnoreError
    public String blake2(final String message,
                         final Encoder encoder) throws UnsupportedOperationException {
        final byte[] hash = blake2(message.getBytes());
        return encoder.encode(hash);
    }

    @IgnoreError
    public byte[] blake2(final byte[] message,
                         final byte[] key,
                         final byte[] salt,
                         final byte[] personal) throws UnsupportedOperationException {
        final byte[] buffer = new byte[CRYPTO_GENERICHASH_BLAKE2B_BYTES];
        sodium().crypto_generichash_blake2b_salt_personal(buffer, CRYPTO_GENERICHASH_BLAKE2B_BYTES,
                message, message.length,
                key, key.length,
                salt, personal);
        return buffer;
    }
}
