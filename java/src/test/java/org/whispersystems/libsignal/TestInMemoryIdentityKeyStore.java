package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class TestInMemoryIdentityKeyStore extends org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore {
  public TestInMemoryIdentityKeyStore() {
    super(generateIdentityKeyPair());
  }

  private static ECKeyPair generateIdentityKeyPair() {
    return Curve.generateKeyPair();
  }

}
