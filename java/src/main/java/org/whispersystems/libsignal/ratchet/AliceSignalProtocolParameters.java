/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;

import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public class AliceSignalProtocolParameters {

  private final ECKeyPair       ourIdentityKey;
  private final ECKeyPair             ourBaseKey;

  private final ECPublicKey           theirIdentityKey;
  private final ECPublicKey           theirSignedPreKey;
  private final Optional<ECPublicKey> theirOneTimePreKey;
  private final ECPublicKey           theirRatchetKey;

  private AliceSignalProtocolParameters(ECKeyPair ourIdentityKey, ECKeyPair ourBaseKey,
                                        ECPublicKey theirIdentityKey, ECPublicKey theirSignedPreKey,
                                        ECPublicKey theirRatchetKey, Optional<ECPublicKey> theirOneTimePreKey)
  {
    this.ourIdentityKey     = ourIdentityKey;
    this.ourBaseKey         = ourBaseKey;
    this.theirIdentityKey   = theirIdentityKey;
    this.theirSignedPreKey  = theirSignedPreKey;
    this.theirRatchetKey    = theirRatchetKey;
    this.theirOneTimePreKey = theirOneTimePreKey;

    if (ourIdentityKey == null || ourBaseKey == null || theirIdentityKey == null ||
        theirSignedPreKey == null || theirRatchetKey == null || theirOneTimePreKey == null)
    {
      throw new IllegalArgumentException("Null values!");
    }
  }

  public ECKeyPair getOurIdentityKey() {
    return ourIdentityKey;
  }

  public ECKeyPair getOurBaseKey() {
    return ourBaseKey;
  }

  public ECPublicKey getTheirIdentityKey() {
    return theirIdentityKey;
  }

  public ECPublicKey getTheirSignedPreKey() {
    return theirSignedPreKey;
  }

  public Optional<ECPublicKey> getTheirOneTimePreKey() {
    return theirOneTimePreKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public ECPublicKey getTheirRatchetKey() {
    return theirRatchetKey;
  }

  public static class Builder {
    private ECKeyPair             ourIdentityKey;
    private ECKeyPair             ourBaseKey;

    private ECPublicKey           theirIdentityKey;
    private ECPublicKey           theirSignedPreKey;
    private ECPublicKey           theirRatchetKey;
    private Optional<ECPublicKey> theirOneTimePreKey;

    public Builder setOurIdentityKey(ECKeyPair ourIdentityKey) {
      this.ourIdentityKey = ourIdentityKey;
      return this;
    }

    public Builder setOurBaseKey(ECKeyPair ourBaseKey) {
      this.ourBaseKey = ourBaseKey;
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

    public Builder setTheirSignedPreKey(ECPublicKey theirSignedPreKey) {
      this.theirSignedPreKey = theirSignedPreKey;
      return this;
    }

    public Builder setTheirOneTimePreKey(Optional<ECPublicKey> theirOneTimePreKey) {
      this.theirOneTimePreKey = theirOneTimePreKey;
      return this;
    }

    public AliceSignalProtocolParameters create() {
      return new AliceSignalProtocolParameters(ourIdentityKey, ourBaseKey, theirIdentityKey,
                                               theirSignedPreKey, theirRatchetKey, theirOneTimePreKey);
    }
  }
}
