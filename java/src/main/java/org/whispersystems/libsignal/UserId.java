package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.Base32;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

// UserId provides functions for encoding and decoding user Ids to/from strings and to/from
// ECPublicKeys.
public class UserId {
    // This alphabet is based on the z-base-32 alphabet which preferences characters that are easier
    // for humans to read. It omits the number 0 and the letters i, l and v. On decoding, we also
    // map the letters i and l to the number 1 and the number 0 to the letter o.
    private static final String alphabet = "ybndrfg8ejkmcpqxot1uw2sza345h769";
    private static final Map<Integer, Integer> replacements = new HashMap<Integer, Integer>();
    static {
        // map some commonly fat-fingered characters to their correct replacements
        replacements.put((int) 'i', (int) '1');
        replacements.put((int) 'l', (int) '1');
        replacements.put((int) '0', (int) 'o');
    }
    private static final Base32 base32 = new Base32(alphabet, replacements);

    private final byte[] bytes;

    public UserId(byte[] bytes) {
        this.bytes = bytes;
    }

    public UserId(IdentityKey identityKey) {
        this(identityKey.serialize());
    }

    public UserId(String string) {
        this(base32.decodeFromString(string.toLowerCase()));
    }

    public IdentityKey getIdentityKey() throws InvalidKeyException {
        return new IdentityKey(Curve.decodePoint(bytes, 0));
    }

    public String toString() {
        return base32.encodeToString(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserId userId = (UserId) o;
        return Arrays.equals(bytes, userId.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}