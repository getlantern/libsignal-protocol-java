/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.IdentityKeyStore;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

  private final ECKeyPair identityKeyPair;

  public InMemoryIdentityKeyStore(ECKeyPair identityKeyPair) {
    this.identityKeyPair     = identityKeyPair;
  }

  @Override
  public ECKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }
}
