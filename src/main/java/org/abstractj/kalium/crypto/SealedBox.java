package org.abstractj.kalium.crypto;

import jnr.ffi.annotations.IgnoreError;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_SEALBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.isValid;

public class SealedBox {

    private final byte[] publicKey;
    private final byte[] privateKey;

    public SealedBox(final byte[] publicKey) {
        this.publicKey = publicKey;
        this.privateKey = null;
    }

    public SealedBox(final String publicKey,
                     final Encoder encoder) {
        this(encoder.decode(publicKey));
    }

    public SealedBox(final byte[] publicKey,
                     final byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public SealedBox(final String publicKey,
                     final String privateKey,
                     final Encoder encoder) {
        this(encoder.decode(publicKey), encoder.decode(privateKey));
    }

    @IgnoreError
    public byte[] encrypt(final byte[] message) {
        if (publicKey == null)
            throw new RuntimeException("Encryption failed. Public key not available.");
        final byte[] ct = new byte[message.length + CRYPTO_BOX_SEALBYTES];
        isValid(sodium().crypto_box_seal(
                        ct, message, message.length, publicKey),
                "Encryption failed");
        return ct;
    }

    @IgnoreError
    public byte[] decrypt(final byte[] ciphertext) {
        if (privateKey == null)
            throw new RuntimeException("Decryption failed. Private key not available.");
        final byte[] message = new byte[ciphertext.length - CRYPTO_BOX_SEALBYTES];
        isValid(sodium().crypto_box_seal_open(
                        message, ciphertext, ciphertext.length, publicKey, privateKey),
                "Decryption failed. Ciphertext failed verification");
        return message;
    }

}
