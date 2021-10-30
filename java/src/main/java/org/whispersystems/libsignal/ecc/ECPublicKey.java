/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.Base32;
import org.whispersystems.libsignal.util.Base810;
import org.whispersystems.libsignal.util.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ECPublicKey implements Comparable<ECPublicKey> {
    private final byte[] bytes;

    public ECPublicKey(byte[] bytes) throws InvalidKeyException {
        if (bytes.length != 32) {
            throw new InvalidKeyException("Bad key length: " + bytes.length);
        }

        this.bytes = bytes;
    }

    public ECPublicKey(String string) throws InvalidKeyException {
        this(Base32.humanFriendly.decodeFromString(string));
    }

    public static ECPublicKey fromNumber(String string) throws InvalidKeyException {
        return new ECPublicKey(Base810.decodeFromString(string, 32));
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String toString() {
        return Base32.humanFriendly.encodeToString(bytes);
    }

    public String toNumber() { return Base810.encodeToString(bytes, 79); }

    public String toShortNumber() { return toNumber().substring(0, 12); }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof ECPublicKey)) return false;

        ECPublicKey that = (ECPublicKey) other;
        return Arrays.equals(this.bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public int compareTo(ECPublicKey another) {
        return new BigInteger(bytes).compareTo(new BigInteger(((ECPublicKey) another).bytes));
    }
}
