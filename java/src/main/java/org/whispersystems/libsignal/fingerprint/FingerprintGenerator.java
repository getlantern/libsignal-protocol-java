/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.List;

public interface FingerprintGenerator {
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               ECPublicKey localIdentityKey,
                               byte[] remoteStableIdentifier,
                               ECPublicKey remoteIdentityKey);

  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               List<ECPublicKey> localIdentityKey,
                               byte[] remoteStableIdentifier,
                               List<ECPublicKey> remoteIdentityKey);
}
