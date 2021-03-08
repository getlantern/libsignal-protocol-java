/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;

import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public class BobSignalProtocolParameters {

  private final ECKeyPair           ourIdentityKey;
  private final ECKeyPair           ourSignedPreKey;
  private final Optional<ECKeyPair> ourOneTimePreKey;
  private final ECKeyPair           ourRatchetKey;

  private final ECPublicKey         theirIdentityKey;
  private final ECPublicKey         theirBaseKey;

  BobSignalProtocolParameters(ECKeyPair ourIdentityKey, ECKeyPair ourSignedPreKey,
                              ECKeyPair ourRatchetKey, Optional<ECKeyPair> ourOneTimePreKey,
                              ECPublicKey theirIdentityKey, ECPublicKey theirBaseKey)
  {
    this.ourIdentityKey   = ourIdentityKey;
    this.ourSignedPreKey  = ourSignedPreKey;
    this.ourRatchetKey    = ourRatchetKey;
    this.ourOneTimePreKey = ourOneTimePreKey;
    this.theirIdentityKey = theirIdentityKey;
    this.theirBaseKey     = theirBaseKey;

    if (ourIdentityKey == null || ourSignedPreKey == null || ourRatchetKey == null ||
        ourOneTimePreKey == null || theirIdentityKey == null || theirBaseKey == null)
    {
      throw new IllegalArgumentException("Null value!");
    }
  }

  public ECKeyPair getOurIdentityKey() {
    return ourIdentityKey;
  }

  public ECKeyPair getOurSignedPreKey() {
    return ourSignedPreKey;
  }

  public Optional<ECKeyPair> getOurOneTimePreKey() {
    return ourOneTimePreKey;
  }

  public ECPublicKey getTheirIdentityKey() {
    return theirIdentityKey;
  }

  public ECPublicKey getTheirBaseKey() {
    return theirBaseKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public ECKeyPair getOurRatchetKey() {
    return ourRatchetKey;
  }

  public static class Builder {
    private ECKeyPair     ourIdentityKey;
    private ECKeyPair           ourSignedPreKey;
    private Optional<ECKeyPair> ourOneTimePreKey;
    private ECKeyPair           ourRatchetKey;

    private ECPublicKey         theirIdentityKey;
    private ECPublicKey         theirBaseKey;

    public Builder setOurIdentityKey(ECKeyPair ourIdentityKey) {
      this.ourIdentityKey = ourIdentityKey;
      return this;
    }

    public Builder setOurSignedPreKey(ECKeyPair ourSignedPreKey) {
      this.ourSignedPreKey = ourSignedPreKey;
      return this;
    }

    public Builder setOurOneTimePreKey(Optional<ECKeyPair> ourOneTimePreKey) {
      this.ourOneTimePreKey = ourOneTimePreKey;
      return this;
    }

    public Builder setTheirIdentityKey(ECPublicKey theirIdentityKey) {
      this.theirIdentityKey = theirIdentityKey;
      return this;
    }

    public Builder setTheirBaseKey(ECPublicKey theirBaseKey) {
      this.theirBaseKey = theirBaseKey;
      return this;
    }

    public Builder setOurRatchetKey(ECKeyPair ourRatchetKey) {
      this.ourRatchetKey = ourRatchetKey;
      return this;
    }

    public BobSignalProtocolParameters create() {
      return new BobSignalProtocolParameters(ourIdentityKey, ourSignedPreKey, ourRatchetKey,
                                             ourOneTimePreKey, theirIdentityKey, theirBaseKey);
    }
  }
}
