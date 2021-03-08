/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

public class DjbECPrivateKey implements ECPrivateKey {

  private final byte[] privateKey;

  DjbECPrivateKey(byte[] privateKey) {
    this.privateKey = privateKey;
  }

  @Override
  public byte[] serialize() {
    return privateKey;
  }

  public byte[] getPrivateKey() {
    return privateKey;
  }
}
