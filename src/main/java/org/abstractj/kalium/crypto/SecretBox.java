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
import static org.abstractj.kalium.crypto.Util.*;

public class SecretBox {

    private final byte[] key;

    public SecretBox(final byte[] key) {
        this.key = key;
        checkLength(key, CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES);
    }

    public SecretBox(final String key,
                     final Encoder encoder) {
        this(encoder.decode(key));
    }

    @IgnoreError
    public byte[] encrypt(final byte[] nonce,
                          final byte[] message) {
        checkLength(nonce, CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES);
        final byte[] msg = Util.prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
        final byte[] ct = Util.zeros(msg.length);
        isValid(sodium().crypto_secretbox_xsalsa20poly1305(ct, msg, msg.length,
                nonce, key), "Encryption failed");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ct);
    }

    @IgnoreError
    public byte[] decrypt(final byte[] nonce,
                          final byte[] ciphertext) {
        checkLength(nonce, CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES);
        final byte[] ct = Util.prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ciphertext);
        final byte[] message = Util.zeros(ct.length);
        isValid(sodium().crypto_secretbox_xsalsa20poly1305_open(message, ct,
                ct.length, nonce, key), "Decryption failed. Ciphertext failed verification");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
    }
}
