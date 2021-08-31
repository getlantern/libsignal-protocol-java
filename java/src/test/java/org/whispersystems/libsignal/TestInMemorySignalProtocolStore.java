package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;

public class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  public TestInMemorySignalProtocolStore() {
    super(generateIdentityKeyPair());
  }

  private static ECKeyPair generateIdentityKeyPair() {
    org.whispersystems.libsignal.ecc.ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

    return new ECKeyPair(identityKeyPairKeys.getPublicKey(),
                                               identityKeyPairKeys.getPrivateKey());
  }
}
