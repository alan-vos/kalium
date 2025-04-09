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
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.encoders.Encoder;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private final byte[] sharedKey;

    @IgnoreError
    public Box(final byte[] publicKey,
               final byte[] privateKey) {
        checkLength(publicKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
        checkLength(privateKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
        sharedKey = new byte[NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_beforenm(
                sharedKey, publicKey, privateKey), "Key agreement failed");
    }

    @IgnoreError
    public Box(final PublicKey publicKey,
               final PrivateKey privateKey) {
        this(publicKey.toBytes(), privateKey.toBytes());
    }

    @IgnoreError
    public Box(final String publicKey,
               final String privateKey,
               final Encoder encoder) {
        this(encoder.decode(publicKey), encoder.decode(privateKey));
    }

    @IgnoreError
    public byte[] encrypt(final byte[] nonce,
                          final byte[] message) {
        checkLength(nonce, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES);
        final byte[] msg = prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
        final byte[] ct = new byte[msg.length];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_afternm(ct, msg,
                msg.length, nonce, sharedKey), "Encryption failed");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ct);
    }

    @IgnoreError
    public byte[] encrypt(final String nonce,
                          final String message,
                          final Encoder encoder) {
        return encrypt(encoder.decode(nonce), encoder.decode(message));
    }

    @IgnoreError
    public byte[] decrypt(final byte[] nonce,
                          final byte[] ciphertext) {
        checkLength(nonce, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES);
        final byte[] ct = prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ciphertext);
        final byte[] message = new byte[ct.length];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_open_afternm(
                        message, ct, message.length, nonce, sharedKey),
                "Decryption failed. Ciphertext failed verification.");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
    }

    @IgnoreError
    public byte[] decrypt(final String nonce,
                          final String ciphertext,
                          final Encoder encoder) {
        return decrypt(encoder.decode(nonce), encoder.decode(ciphertext));
    }
}
