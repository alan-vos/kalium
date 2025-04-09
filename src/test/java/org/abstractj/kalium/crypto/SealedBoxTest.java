package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.KeyPair;
import org.junit.Test;

import java.security.SecureRandom;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.junit.Assert.assertArrayEquals;

public class SealedBoxTest {

    @Test
    public void testEncryptDecrypt()  {
        final SecureRandom r = new SecureRandom();
        final KeyPair keyPair = new KeyPair(new byte[CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES]);
        final byte[] sk = keyPair.getPrivateKey().toBytes();
        final byte[] pk = keyPair.getPublicKey().toBytes();
        final byte[] m = new byte[r.nextInt(1000)];

        r.nextBytes(m);
        final SealedBox sb = new SealedBox(pk);
        final byte[] c = sb.encrypt(m);

        final SealedBox sb2 = new SealedBox(pk, sk);
        final byte[] m2 = sb2.decrypt(c);
        assertArrayEquals(m, m2);
    }

    @Test
    public void testEncryptDecryptMultPublicKeys()  {
        final SecureRandom r = new SecureRandom();
        final KeyPair keyPair = new KeyPair(new byte[CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES]);
        final byte[] sk = keyPair.getPrivateKey().toBytes();
        final byte[] pk1 = keyPair.getPublicKey().toBytes();
        final byte[] pk2 = new byte[pk1.length];

        sodium().crypto_scalarmult_base(pk2, sk);

        final byte[] m = new byte[r.nextInt(1000)];
        r.nextBytes(m);

        final SealedBox sb1 = new SealedBox(pk1);
        final byte[] c1 = sb1.encrypt(m);

        final SealedBox sb2 = new SealedBox(pk2);
        final byte[] c2 = sb2.encrypt(m);

        final SealedBox sb3 = new SealedBox(pk1, sk);
        final byte[] m2 = sb3.decrypt(c1);
        final byte[] m3 = sb3.decrypt(c2);
        assertArrayEquals(m, m2);
        assertArrayEquals(m2, m3);
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptFailsFlippedKeys()  {
        final SecureRandom r = new SecureRandom();
        final byte[] pk = new byte[CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES];
        final byte[] sk = new byte[CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES];
        final byte[] m = new byte[r.nextInt(1000)];

        sodium().crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
        r.nextBytes(m);

        final SealedBox sb = new SealedBox(pk);
        final byte[] c = sb.encrypt(m);
        final SealedBox sb2 = new SealedBox(sk, pk);
        sb2.decrypt(c);
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptFailsWithNull()  {
        final SecureRandom r = new SecureRandom();
        final byte[] pk = null;
        final byte[] sk = null;
        final byte[] m = new byte[r.nextInt(1000)];

        final SealedBox sb = new SealedBox(pk);
        final byte[] c = sb.encrypt(m);
        final SealedBox sb2 = new SealedBox(sk, pk);
        sb2.decrypt(c);
    }
}
