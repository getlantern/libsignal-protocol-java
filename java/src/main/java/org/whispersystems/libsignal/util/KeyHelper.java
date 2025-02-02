/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.util;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

/**
 * Helper class for generating keys of different types.
 *
 * @author Moxie Marlinspike
 */
public class KeyHelper {

  private KeyHelper() {}

  /**
   * Generate an identity key pair.  Clients should only do this once,
   * at install time.
   *
   * @return the generated ECKeyPair.
   */
  public static ECKeyPair generateIdentityKeyPair() {
    ECKeyPair   keyPair   = Curve.generateKeyPair();
    ECPublicKey publicKey = keyPair.getPublicKey();
    return new ECKeyPair(publicKey, keyPair.getPrivateKey());
  }

  public static int getRandomSequence(int max) {
    try {
      return SecureRandom.getInstance("SHA1PRNG").nextInt(max);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Generate a list of PreKeys.  Clients should do this at install time, and
   * subsequently any time the list of PreKeys stored on the server runs low.
   * <p>
   * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
   * store PreKeys in a circular buffer, so that they are repeated as infrequently
   * as possible.
   *
   * @param start The starting PreKey ID, inclusive.
   * @param count The number of PreKeys to generate.
   * @return the list of generated PreKeyRecords.
   */
  public static List<PreKeyRecord> generatePreKeys(int start, int count) {
    List<PreKeyRecord> results = new LinkedList<>();

    start--;

    for (int i=0;i<count;i++) {
      results.add(new PreKeyRecord(((start + i) % (Medium.MAX_VALUE-1)) + 1, Curve.generateKeyPair()));
    }

    return results;
  }

  /**
   * Generate a signed PreKey
   *
   * @param identityKeyPair The local client's identity key pair.
   * @param signedPreKeyId The PreKey id to assign the generated signed PreKey
   *
   * @return the generated signed PreKey
   * @throws InvalidKeyException when the provided identity key is invalid
   */
  public static SignedPreKeyRecord generateSignedPreKey(ECKeyPair identityKeyPair, int signedPreKeyId)
      throws InvalidKeyException
  {
    ECKeyPair keyPair   = Curve.generateKeyPair();
    byte[]    signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().getBytes());

    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }


  public static ECKeyPair generateSenderSigningKey() {
    return Curve.generateKeyPair();
  }

  public static byte[] generateSenderKey() {
    try {
      byte[] key = new byte[32];
      SecureRandom.getInstance("SHA1PRNG").nextBytes(key);

      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public static int generateSenderKeyId() {
    try {
      return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

}
