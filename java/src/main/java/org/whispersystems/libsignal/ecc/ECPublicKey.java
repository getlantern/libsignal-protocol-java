/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.Base32;
import org.whispersystems.libsignal.util.Hex;
import org.whispersystems.libsignal.util.InvalidCharacterException;

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
        this(decodeFromString(string));
    }

    private static byte[] decodeFromString(String string) throws InvalidKeyException {
        try {
            return Base32.humanFriendly.decodeFromString(string);
        } catch (InvalidCharacterException ice) {
            throw new InvalidKeyException(ice);
        }
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String toString() {
        return Base32.humanFriendly.encodeToString(bytes);
    }

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
