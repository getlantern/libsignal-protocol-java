/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;

import java.util.Arrays;

import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair() {
    Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();

    return new ECKeyPair(new DjbECPublicKey(keyPair.getPublicKey()),
                         new DjbECPrivateKey(keyPair.getPrivateKey()));
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
      if (bytes == null || bytes.length < 32) {
        throw new InvalidKeyException("Bad key length: " + bytes.length);
      }

      if (bytes.length > 32) {
        bytes = Arrays.copyOf(bytes, 32);
      }

      return new DjbECPublicKey(bytes);
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    return new DjbECPrivateKey(bytes);
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws InvalidKeyException
  {
    if (publicKey == null) {
      throw new InvalidKeyException("public value is null");
    }

    if (privateKey == null) {
      throw new InvalidKeyException("private value is null");
    }


    return Curve25519.getInstance(BEST)
                     .calculateAgreement(((DjbECPublicKey) publicKey).getPublicKey(),
                                         ((DjbECPrivateKey) privateKey).getPrivateKey());
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .verifySignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .calculateSignature(((DjbECPrivateKey) signingKey).getPrivateKey(), message);
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .calculateVrfSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .verifyVrfSignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
  }

}
