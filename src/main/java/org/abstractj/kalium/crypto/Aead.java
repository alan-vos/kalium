package org.abstractj.kalium.crypto;

import jnr.ffi.annotations.IgnoreError;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

@SuppressWarnings("unused")
public class Aead {

    private final byte[] key;
    private boolean aesGcm = false;

    public Aead(final byte[] key) {
        this.key = key;
        // both CHACHAPOLY and AESGCM use 32 byte keys
        checkLength(key, CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
        // needs to be called here for aes256gcm_is_available() to work
        sodium().sodium_init();
    }

    public Aead(final String key,
                final Encoder encoder) {
        this(encoder.decode(key));
    }

    public Aead useAesGcm() {
        // This works now.
        aesGcm = true;
        return this;
    }

    @IgnoreError
    public byte[] encrypt(final byte[] publicNonce,
                          final byte[] message,
                          final byte[] additionalData) {
        return aesGcm ?
                encryptAesGcm(publicNonce, message, additionalData) :
                encryptChaChaPoly(publicNonce, message, additionalData);
    }

    @IgnoreError
    protected byte[] encryptChaChaPoly(final byte[] publicNonce,
                                       final byte[] message,
                                       final byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        final byte[] ct = zeros(message.length + CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_encrypt(ct, null,
                        message, message.length, additionalData,
                        additionalData.length, null, publicNonce, key),
                "Encryption failed");

        return ct;
    }

    @IgnoreError
    protected byte[] encryptAesGcm(final byte[] publicNonce,
                                   final byte[] message,
                                   final byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        final byte[] ct = zeros(message.length + CRYPTO_AEAD_AES256GCM_ABYTES);
        isValid(sodium().crypto_aead_aes256gcm_encrypt(ct, null,
                        message, message.length, additionalData,
                        additionalData.length, null, publicNonce, key),
                "Encryption failed");
        return ct;
    }

    @IgnoreError
    public byte[] decrypt(final byte[] publicNonce,
                          final byte[] ciphertext,
                          final byte[] additionalData) {
        return aesGcm ?
                decryptAesGcm(publicNonce, ciphertext, additionalData) :
                decryptChaChaPoly(publicNonce, ciphertext, additionalData);
    }

    @IgnoreError
    protected byte[] decryptChaChaPoly(final byte[] publicNonce,
                                       final byte[] ciphertext,
                                       final byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        final byte[] msg = zeros(ciphertext.length - CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_decrypt(msg, null,
                        null, ciphertext, ciphertext.length, additionalData,
                        additionalData.length, publicNonce, key),
                "Decryption failed. Ciphertext failed verification");
        return msg;
    }

    @IgnoreError
    protected byte[] decryptAesGcm(final byte[] publicNonce,
                                   final byte[] ciphertext,
                                   final byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        final byte[] msg = zeros(ciphertext.length - CRYPTO_AEAD_AES256GCM_ABYTES);
        isValid(sodium().crypto_aead_aes256gcm_decrypt(msg, null,
                        null, ciphertext, ciphertext.length, additionalData,
                        additionalData.length, publicNonce, key),
                "Decryption failed. Ciphertext failed verification");
        return msg;
    }
}
