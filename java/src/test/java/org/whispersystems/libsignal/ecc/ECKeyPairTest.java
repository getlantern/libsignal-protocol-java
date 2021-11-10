package org.whispersystems.libsignal.ecc;

import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.InvalidCharacterException;

import java.util.Arrays;

public class ECKeyPairTest extends TestCase {
    public void testBytes() throws InvalidKeyException {
        ECKeyPair pair1 = Curve.generateKeyPair();
        ECKeyPair pair2 = ECKeyPair.fromBytes(pair1.getBytes());
        assertEquals(pair1.getPublicKey(), pair2.getPublicKey());
        assertTrue(Arrays.equals(pair1.getPrivateKey().getBytes(), pair2.getPrivateKey().getBytes()));
    }
}
