package org.whispersystems.libsignal;

import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;


public class SignalProtocolAddressTest extends TestCase {

    public void testSerializationSuccess()
            throws InvalidAddressException, InvalidKeyException {
        ECKeyPair keyPair = Curve.generateKeyPair();
        SignalProtocolAddress address = new SignalProtocolAddress(keyPair.getPublicKey(), DeviceId.random());
        SignalProtocolAddress roundTrippedAddress = new SignalProtocolAddress(address.toString());
        assertEquals(address, roundTrippedAddress);
    }

    public void testSerializationFailure()
            throws InvalidAddressException, InvalidKeyException {
        try {
            new SignalProtocolAddress("blah");
            fail("Bad address should have thrown an InvalidAddressException");
        } catch (InvalidAddressException iae) {
            // expected
        }

        try {
            new SignalProtocolAddress("blah:blah");
            fail("Bad key in address should have thrown an InvalidKeyException");
        } catch (InvalidKeyException ike) {
            // expected
        }
    }
}
