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

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.encoders.Encoder.HEX;

public class PrivateKey implements Key {

    private final byte[] secretKey;

    public PrivateKey(final byte[] secretKey) {
        this.secretKey = secretKey;
        checkLength(secretKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
    }

    public PrivateKey(final String secretKey) {
        this.secretKey = HEX.decode(secretKey);
        checkLength(this.secretKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
    }

    @Override
    public byte[] toBytes() {
        return secretKey;
    }

    @Override
    public String toString() {
        return HEX.encode(secretKey);
    }
}
