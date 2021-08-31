package org.whispersystems.libsignal.util;

import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.Comparator;

public class IdentityKeyComparator extends ByteArrayComparator implements Comparator<ECPublicKey> {

  @Override
  public int compare(ECPublicKey first, ECPublicKey second) {
    return compare(first.getBytes(), second.getBytes());
  }
}
