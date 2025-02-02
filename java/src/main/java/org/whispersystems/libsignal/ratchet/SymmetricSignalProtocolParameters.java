/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;

import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class SymmetricSignalProtocolParameters {

  private final ECKeyPair       ourBaseKey;
  private final ECKeyPair       ourRatchetKey;
  private final ECKeyPair ourIdentityKey;

  private final ECPublicKey     theirBaseKey;
  private final ECPublicKey     theirRatchetKey;
  private final ECPublicKey     theirIdentityKey;

  SymmetricSignalProtocolParameters(ECKeyPair ourBaseKey, ECKeyPair ourRatchetKey,
                                    ECKeyPair ourIdentityKey, ECPublicKey theirBaseKey,
                                    ECPublicKey theirRatchetKey, ECPublicKey theirIdentityKey)
  {
    this.ourBaseKey       = ourBaseKey;
    this.ourRatchetKey    = ourRatchetKey;
    this.ourIdentityKey   = ourIdentityKey;
    this.theirBaseKey     = theirBaseKey;
    this.theirRatchetKey  = theirRatchetKey;
    this.theirIdentityKey = theirIdentityKey;

    if (ourBaseKey == null || ourRatchetKey == null || ourIdentityKey == null ||
        theirBaseKey == null || theirRatchetKey == null || theirIdentityKey == null)
    {
      throw new IllegalArgumentException("Null values!");
    }
  }

  public ECKeyPair getOurBaseKey() {
    return ourBaseKey;
  }

  public ECKeyPair getOurRatchetKey() {
    return ourRatchetKey;
  }

  public ECKeyPair getOurIdentityKey() {
    return ourIdentityKey;
  }

  public ECPublicKey getTheirBaseKey() {
    return theirBaseKey;
  }

  public ECPublicKey getTheirRatchetKey() {
    return theirRatchetKey;
  }

  public ECPublicKey getTheirIdentityKey() {
    return theirIdentityKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private ECKeyPair       ourBaseKey;
    private ECKeyPair       ourRatchetKey;
    private ECKeyPair ourIdentityKey;

    private ECPublicKey     theirBaseKey;
    private ECPublicKey     theirRatchetKey;
    private ECPublicKey     theirIdentityKey;

    public Builder setOurBaseKey(ECKeyPair ourBaseKey) {
      this.ourBaseKey = ourBaseKey;
      return this;
    }

    public Builder setOurRatchetKey(ECKeyPair ourRatchetKey) {
      this.ourRatchetKey = ourRatchetKey;
      return this;
    }

    public Builder setOurIdentityKey(ECKeyPair ourIdentityKey) {
      this.ourIdentityKey = ourIdentityKey;
      return this;
    }

    public Builder setTheirBaseKey(ECPublicKey theirBaseKey) {
      this.theirBaseKey = theirBaseKey;
      return this;
    }

    public Builder setTheirRatchetKey(ECPublicKey theirRatchetKey) {
      this.theirRatchetKey = theirRatchetKey;
      return this;
    }

    public Builder setTheirIdentityKey(ECPublicKey theirIdentityKey) {
      this.theirIdentityKey = theirIdentityKey;
      return this;
    }

    public SymmetricSignalProtocolParameters create() {
      return new SymmetricSignalProtocolParameters(ourBaseKey, ourRatchetKey, ourIdentityKey,
                                                   theirBaseKey, theirRatchetKey, theirIdentityKey);
    }
  }
}
