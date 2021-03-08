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

import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair() {
    Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();

    try {
      return new ECKeyPair(new ECPublicKey(keyPair.getPublicKey()),
              new ECPrivateKey(keyPair.getPrivateKey()));
    } catch (InvalidKeyException e) {
      throw new AssertionError("Invalid key on generation, this should never happen", e);
    }
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
                     .calculateAgreement(((ECPublicKey) publicKey).getBytes(),
                                         ((ECPrivateKey) privateKey).getBytes());
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .verifySignature(((ECPublicKey) signingKey).getBytes(), message, signature);
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .calculateSignature(((ECPrivateKey) signingKey).getBytes(), message);
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .calculateVrfSignature(((ECPrivateKey)signingKey).getBytes(), message);
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return Curve25519.getInstance(BEST)
                     .verifyVrfSignature(((ECPublicKey) signingKey).getBytes(), message, signature);
  }

}
