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

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SIGN_ED25519_BYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.encoders.Encoder.HEX;

public class VerifyKey {

    private final byte[] key;

    public VerifyKey(final byte[] key) {
        checkLength(key, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
        this.key = key;
    }

    public VerifyKey(final String key,
                     final Encoder encoder) {
        this(encoder.decode(key));
    }

    public boolean verify(final byte[] message,
                          final byte[] signature) {
        checkLength(signature, CRYPTO_SIGN_ED25519_BYTES);
        return isValid(sodium().crypto_sign_ed25519_verify_detached(signature, message, message.length, key), "signature was forged or corrupted");
    }

    public boolean verify(final String message,
                          final String signature,
                          final Encoder encoder) {
        return verify(encoder.decode(message), encoder.decode(signature));
    }

    public byte[] toBytes() {
        return key;
    }

    @Override
    public String toString() {
        return HEX.encode(key);
    }
}
