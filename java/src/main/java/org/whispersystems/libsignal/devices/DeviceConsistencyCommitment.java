package org.whispersystems.libsignal.devices;

import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DeviceConsistencyCommitment {

  private static final String VERSION = "DeviceConsistencyCommitment_V0";

  private final int generation;
  private final byte[] serialized;

  public DeviceConsistencyCommitment(int generation, List<ECPublicKey> identityKeys) {
    try {
      ArrayList<ECPublicKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
      Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      messageDigest.update(VERSION.getBytes());
      messageDigest.update(ByteUtil.intToByteArray(generation));

      for (ECPublicKey commitment : sortedIdentityKeys) {
        messageDigest.update(commitment.getBytes());
      }

      this.generation = generation;
      this.serialized = messageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] toByteArray() {
    return serialized;
  }

  public int getGeneration() {
    return generation;
  }


}
