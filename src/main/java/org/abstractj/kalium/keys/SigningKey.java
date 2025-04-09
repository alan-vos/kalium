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

import jnr.ffi.annotations.IgnoreError;
import jnr.ffi.byref.LongLongByReference;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;
import static org.abstractj.kalium.encoders.Encoder.HEX;

public class SigningKey {

    private final byte[] seed;
    private final byte[] secretKey;
    private final VerifyKey verifyKey;

    @IgnoreError
    public SigningKey(final byte[] seed) {
        checkLength(seed, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
        this.seed = seed;
        this.secretKey = zeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES * 2);
        final byte[] publicKey = zeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
        isValid(sodium().crypto_sign_ed25519_seed_keypair(publicKey, secretKey, seed),
                "Failed to generate a key pair");
        this.verifyKey = new VerifyKey(publicKey);
    }

    public SigningKey() {
        this(new Random().randomBytes(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES));
    }

    public SigningKey(final String seed,
                      final Encoder encoder) {
        this(encoder.decode(seed));
    }

    public VerifyKey getVerifyKey() {
        return this.verifyKey;
    }

    @IgnoreError
    public byte[] sign(final byte[] message) {
        final byte[] signature = new byte[CRYPTO_SIGN_ED25519_BYTES];
        LongLongByReference bufferLen = new LongLongByReference(0);
        sodium().crypto_sign_ed25519_detached(signature, bufferLen, message, message.length, secretKey);
        return signature;
    }

    public String sign(final String message,
                       final Encoder encoder) {
        final byte[] signature = sign(encoder.decode(message));
        return encoder.encode(signature);
    }

    public byte[] toBytes() {
        return seed;
    }

    @Override
    public String toString() {
        return HEX.encode(seed);
    }
}
