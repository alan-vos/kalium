/**
 * Copyright 2017 Bruno Oliveira, and individual contributors
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

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SHORTHASH_SIPHASH24_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;

public class ShortHash {

    @IgnoreError
    public byte[] siphash24(final byte[] message,
                            final byte[] key) {
        final byte[] buffer = new byte[CRYPTO_SHORTHASH_SIPHASH24_BYTES];
        checkLength(key, CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES);
        isValid(sodium().crypto_shorthash_siphash24(buffer, message, message.length, key), "Hashing failed");
        return buffer;
    }

}
