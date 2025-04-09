package org.abstractj.kalium.crypto;

import jnr.ffi.annotations.IgnoreError;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;

public class Password {

    public Password() {
    }

    @IgnoreError
    public byte[] deriveKey(final int length,
                            final byte[] passwd,
                            final byte[] salt,
                            final int opslimit,
                            final long memlimit) {
        final byte[] buffer = new byte[length];
        sodium().crypto_pwhash_scryptsalsa208sha256(buffer, buffer.length, passwd, passwd.length, salt, opslimit, memlimit);
        return buffer;
    }

    @IgnoreError
    public String hash(final byte[] passwd,
                       final Encoder encoder,
                       final byte[] salt,
                       final int opslimit,
                       final long memlimit) {
        final byte[] buffer = deriveKey(CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES, passwd, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    @IgnoreError
    public String hash(final int length,
                       final byte[] passwd,
                       final Encoder encoder,
                       final byte[] salt,
                       final int opslimit,
                       final long memlimit) {
        final byte[] buffer = deriveKey(length, passwd, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    @IgnoreError
    public String hash(final byte[] passwd,
                       final Encoder encoder,
                       final int opslimit,
                       final long memlimit) {
        final byte[] buffer = new byte[CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES];
        sodium().crypto_pwhash_scryptsalsa208sha256_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    @IgnoreError
    public boolean verify(final byte[] hashed_passwd,
                          final byte[] passwd) {
        final int result = sodium().crypto_pwhash_scryptsalsa208sha256_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }
}
