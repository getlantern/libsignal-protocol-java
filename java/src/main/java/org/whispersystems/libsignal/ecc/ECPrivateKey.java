/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.whispersystems.libsignal.util.Base32;

public class ECPrivateKey {
    protected final byte[] bytes;

    public ECPrivateKey(byte[] bytes) {
        this.bytes = bytes;
    }

    public ECPrivateKey(String string) {
        this(Base32.humanFriendly.decodeFromString(string));
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String toString() {
        return Base32.humanFriendly.encodeToString(bytes);
    }
}
