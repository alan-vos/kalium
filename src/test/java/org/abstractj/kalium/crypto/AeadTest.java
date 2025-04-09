package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;

public class AeadTest {
    @Test
    public void testEncrypt() {
        final byte[] key = HEX.decode(AEAD_KEY);
        final byte[] publicNonce = HEX.decode(AEAD_NONCE);
        final byte[] message = HEX.decode(AEAD_MESSAGE);
        final byte[] ad = HEX.decode(AEAD_AD);

        final Aead aead = new Aead(key);
        final byte[] ct = aead.encrypt(publicNonce, message, ad);
        assertArrayEquals(HEX.decode(AEAD_CT), ct);
    }

    @Test
    public void testDecrypt() {
        final byte[] key = HEX.decode(AEAD_KEY);
        final byte[] publicNonce = HEX.decode(AEAD_NONCE);
        final byte[] ct = HEX.decode(AEAD_CT);
        final byte[] ad = HEX.decode(AEAD_AD);

        final Aead aead = new Aead(key);
        final byte[] message = aead.decrypt(publicNonce, ct, ad);
        assertArrayEquals(HEX.decode(AEAD_MESSAGE), message);
    }

    @Test
    public void testAES256GCM() {
        sodium().sodium_init();
        final byte[] key = HEX.decode(AEAD_KEY);
        final byte[] publicNonce = new Random().randomBytes(NaCl.Sodium.CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        final byte[] message = HEX.decode(AEAD_MESSAGE);
        final byte[] ad = HEX.decode(AEAD_AD);

        final Aead aead = new Aead(key).useAesGcm();
        final byte[] ct = aead.encrypt(publicNonce, message, ad);
        final byte[] msg2 = aead.decrypt(publicNonce, ct, ad);
        assertArrayEquals(message, msg2);
    }
}
