/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle {

  private int         preKeyId;
  private ECPublicKey preKeyPublic;

  private int         signedPreKeyId;
  private ECPublicKey signedPreKeyPublic;
  private byte[]      signedPreKeySignature;

  private ECPublicKey identityKey;

  public PreKeyBundle(int preKeyId, ECPublicKey preKeyPublic,
                      int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                      ECPublicKey identityKey)
  {
    this.preKeyId              = preKeyId;
    this.preKeyPublic          = preKeyPublic;
    this.signedPreKeyId        = signedPreKeyId;
    this.signedPreKeyPublic    = signedPreKeyPublic;
    this.signedPreKeySignature = signedPreKeySignature;
    this.identityKey           = identityKey;
  }

  /**
   * @return the unique key ID for this PreKey.
   */
  public int getPreKeyId() {
    return preKeyId;
  }

  /**
   * @return the public key for this PreKey.
   */
  public ECPublicKey getPreKey() {
    return preKeyPublic;
  }

  /**
   * @return the unique key ID for this signed prekey.
   */
  public int getSignedPreKeyId() {
    return signedPreKeyId;
  }

  /**
   * @return the signed prekey for this PreKeyBundle.
   */
  public ECPublicKey getSignedPreKey() {
    return signedPreKeyPublic;
  }

  /**
   * @return the signature over the signed  prekey.
   */
  public byte[] getSignedPreKeySignature() {
    return signedPreKeySignature;
  }

  /**
   * @return the {@link org.whispersystems.libsignal.ecc.ECPublicKey} of this PreKeys owner.
   */
  public ECPublicKey getIdentityKey() {
    return identityKey;
  }
}
