/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

public class UntrustedIdentityException extends Exception {

  private final UserId userId;
  private final IdentityKey key;

  public UntrustedIdentityException(UserId userId, IdentityKey key) {
    this.userId = userId;
    this.key  = key;
  }

  public IdentityKey getUntrustedIdentity() {
    return key;
  }

  public UserId getUserId() {
    return userId;
  }
}
