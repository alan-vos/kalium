package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

@SuppressWarnings("unused")
public class Aead {

    private final byte[] key;

    private boolean aesGcm = false;

    public Aead(byte[] key) {
        this.key = key;
        // both CHACHAPOLY and AESGCM use 32 byte keys
        checkLength(key, CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
        sodium().sodium_init(); // needs to be called here for aes256gcm_is_available() to work

    }

    public Aead(String key, Encoder encoder) {
        this(encoder.decode(key));
    }

    public Aead useAesGcm() {
        // This works now.
        aesGcm = true;
        return this;
    }

    public byte[] encrypt(byte[] publicNonce, byte[] message, byte[] additionalData) {
        return aesGcm ?
                encryptAesGcm(publicNonce, message, additionalData) :
                encryptChaChaPoly(publicNonce, message, additionalData);
    }

    protected byte[] encryptChaChaPoly(byte[] publicNonce, byte[] message, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        byte[] ct = zeros(message.length + CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_encrypt(ct, null,
                        message, message.length, additionalData,
                        additionalData.length, null, publicNonce, key),
                "Encryption failed");

        return ct;
    }

    protected byte[] encryptAesGcm(byte[] publicNonce, byte[] message, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        byte[] ct = zeros(message.length + CRYPTO_AEAD_AES256GCM_ABYTES);
        isValid(sodium().crypto_aead_aes256gcm_encrypt(ct, null,
                        message, message.length, additionalData,
                        additionalData.length, null, publicNonce, key),
                "Encryption failed");

        return ct;
    }

    public byte[] decrypt(byte[] publicNonce, byte[] ciphertext, byte[] additionalData) {
        return aesGcm ?
                decryptAesGcm(publicNonce, ciphertext, additionalData) :
                decryptChaChaPoly(publicNonce, ciphertext, additionalData);
    }

    protected byte[] decryptChaChaPoly(byte[] publicNonce, byte[] ciphertext, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        byte[] msg = zeros(ciphertext.length - CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_decrypt(msg, null,
                        null, ciphertext, ciphertext.length, additionalData,
                        additionalData.length, publicNonce, key),
                "Decryption failed. Ciphertext failed verification");

        return msg;
    }

    protected byte[] decryptAesGcm(byte[] publicNonce, byte[] ciphertext, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        byte[] msg = zeros(ciphertext.length - CRYPTO_AEAD_AES256GCM_ABYTES);
        isValid(sodium().crypto_aead_aes256gcm_decrypt(msg, null,
                        null, ciphertext, ciphertext.length, additionalData,
                        additionalData.length, publicNonce, key),
                "Decryption failed. Ciphertext failed verification");

        return msg;
    }
}
