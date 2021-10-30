package org.whispersystems.libsignal.ecc;

import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.InvalidCharacterException;

public class ECPublicKeyTest extends TestCase {
    public void testShort() {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        String keyString = key.toString().substring(0, 51);
        try {
            new ECPublicKey(keyString);
            fail("too short key should cause InvalidKeyException");
        } catch (InvalidKeyException ike) {
            // expected
        }
    }

    public void testLong() {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        String keyString = key.toString() + "a";
        try {
            new ECPublicKey(keyString);
            fail("too long key should cause InvalidKeyException");
        } catch (InvalidKeyException ike) {
            // expected
        }
    }

    public void testCorrupted() throws InvalidKeyException {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        String keyString = key.toString() + "=";
        try {
            new ECPublicKey(keyString);
            fail("corrupted key should cause InvalidCharacterException");
        } catch (InvalidCharacterException ice) {
            // expected
            System.out.println(ice.toString());
        }
    }

    public void testReplacement() throws InvalidKeyException {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        String keyStringA = "o" + key.toString().substring(1, 52);
        String keyStringB = "0" + key.toString().substring(1, 52);

        ECPublicKey keyA = new ECPublicKey(keyStringA);
        ECPublicKey keyB = new ECPublicKey(keyStringB);
        assertEquals(
                "keys with equivalent replacement characters o and 0 should be identical",
                keyA,
                keyB);
        assertEquals(
                "key string with character 0 should normalize to o",
                keyStringA,
                keyB.toString());
    }

    public void testRoundTrip() throws InvalidKeyException {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        assertEquals(
                "round-tripped key should equal itself",
                key,
                new ECPublicKey(key.toString()));
    }

    public void testRoundTripNumber() throws InvalidKeyException {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        assertEquals(
                "round-tripped key should equal itself",
                key,
                ECPublicKey.fromNumber(key.toNumber()));
    }

    public void testShortNumber() throws InvalidKeyException {
        ECPublicKey key = Curve.generateKeyPair().getPublicKey();
        assertTrue(
                "short number should be a prefix of full number",
                key.toNumber().startsWith(key.toShortNumber()));
    }
}
