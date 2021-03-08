/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.util.HashMap;
import java.util.Map;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

  private final IdentityKeyPair identityKeyPair;

  public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair) {
    this.identityKeyPair     = identityKeyPair;
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }
}
