/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.ByteUtil;

public class ECKeyPair {

  private final ECPublicKey  publicKey;
  private final ECPrivateKey privateKey;

  public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public static ECKeyPair fromBytes(byte[] bytes) throws InvalidKeyException {
    if (bytes.length != 64) {
      throw new InvalidKeyException("Bad keypair length: " + bytes.length);
    }

    byte[][] parts = ByteUtil.split(bytes, 32, 32);
    return new ECKeyPair(new ECPublicKey(parts[0]), new ECPrivateKey(parts[1]));
  }

  public byte[] getBytes() {
    return ByteUtil.combine(publicKey.getBytes(), privateKey.getBytes());
  }

  public ECPublicKey getPublicKey() {
    return publicKey;
  }

  public ECPrivateKey getPrivateKey() {
    return privateKey;
  }
}
