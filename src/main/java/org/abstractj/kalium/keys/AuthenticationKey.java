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

import jnr.ffi.annotations.IgnoreError;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_AUTH_HMACSHA512256_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_AUTH_HMACSHA512256_KEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.encoders.Encoder.HEX;


public class AuthenticationKey implements Key {

    private final byte[] key;

    public AuthenticationKey(final byte[] key) {
        this.key = key;
        checkLength(key, CRYPTO_AUTH_HMACSHA512256_KEYBYTES);
    }

    public AuthenticationKey(final String key,
                             final Encoder encoder) {
        this(encoder.decode(key));
    }

    @IgnoreError
    public byte[] sign(final byte[] message) {
        final byte[] mac = new byte[CRYPTO_AUTH_HMACSHA512256_BYTES];
        sodium().crypto_auth_hmacsha512256(mac, message, message.length, key);
        return mac;
    }

    public String sign(final String message,
                       final Encoder encoder) {
        final byte[] signature = sign(encoder.decode(message));
        return encoder.encode(signature);
    }

    public boolean verify(final byte[] message,
                          final byte[] signature) {
        checkLength(signature, CRYPTO_AUTH_HMACSHA512256_BYTES);
        return isValid(sodium().crypto_auth_hmacsha512256_verify(signature, message, message.length, key), "signature was forged or corrupted");
    }

    public boolean verify(final String message,
                          final String signature,
                          final Encoder encoder) {
        return verify(encoder.decode(message), encoder.decode(signature));
    }

    @Override
    public byte[] toBytes() {
        return key;
    }

    @Override
    public String toString() {
        return HEX.encode(key);
    }

}
