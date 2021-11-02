package org.whispersystems.libsignal.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides a human-friendly encoding that looks like a phone number but isn't usually a dialable
 * phone number, because it doesn't start with 0 or 1 (as is required in most countries). This
 * encoding treats a byte array as a big-endian number. The first (most significant) 2 bits of data
 * are encoded using a modified base4 encoding (digits 2, 3, 4, 6 instead of the standard 0-4) and the
 * remaining data is encoded in base9 (omitting digit 5) and left-padded with '0's to meet the desired length.
 *
 * This encoding permits the inclusion of arbitrary '5's anywhere in the encoded string, which it simply ignores. This
 * can be used to visually differentiate the beginning of two otherwise very similar numbers, for example, given:
 *
 * 2222222222222222222222222222222222222222222222222222222222222222222222222222222
 * 2222222222222222222222222222222222222222222222222222222222222222222222222222223
 *
 * We can change the 2nd number to the following equivalent value
 *
 * 522222222222252222222222222222222222222222222222222222222222222222222222222222223
 */
public class ChatNumberEncoding {
    private static final Map<Byte, Character> base4Table = new HashMap<>();
    private static final Map<Character, Byte> base4TableReverse = new HashMap<>();

    static {
        addBase4Mapping((byte) 0, '2');
        addBase4Mapping((byte) 1, '3');
        addBase4Mapping((byte) 2, '4');
        addBase4Mapping((byte) 3, '6');
    }

    private static void addBase4Mapping(final Byte b, final Character c) {
        base4Table.put(b, c);
        base4TableReverse.put(c, b);
    }

    /**
     * Encodes the given bytes using ChatNumber encoding. The resulting string will be of target
     * length using '0's after the first digit in order to pad up to the targetLength.
     *
     * @param b
     * @param targetLength
     * @return
     */
    public static String encodeToString(final byte[] b, final int targetLength) {
        byte[] _b = ByteUtil.copyFrom(b);
        byte head = (byte) (byteToUnsigned(_b[0]) >>> 6);
        _b[0] = (byte) (byteToUnsigned(_b[0]) << 2);
        String tail = shiftBase9(new BigInteger(1, _b).toString(9));
        StringBuilder result = new StringBuilder(targetLength);
        result.append(base4Table.get(head));
        int padding = targetLength - 1 - tail.length();
        if (padding < 0) {
            padding = 0;
        }
        for (int i = 0; i < padding; i++) {
            result.append('0');
        }
        result.append(tail);
        return result.toString();
    }

    /**
     * Decodes the given ChatNumber string into a byte[] of targetSize. If the string doesn't
     * contain enough data to fill targetSize, the byte[] will contain leading zeros.
     *
     * This function ignores any leading characters other than 2, 3, 4 or 6, and any subsequent 5s.
     *
     * @param s
     * @param targetSize
     * @return
     */
    public static byte[] decodeFromString(String s, final int targetSize) {
        s = s.replaceAll("^[015789]+", "");
        byte head = base4TableReverse.get(s.charAt(0));
        BigInteger _tail = new BigInteger(unshiftBase9(s.substring(1)), 9);
        ByteBuffer buf = ByteBuffer.allocate(targetSize);
        for (int i = targetSize / 4 - 1; i >= 0; i--) {
            buf.putInt(i * 4, _tail.intValue());
            _tail = _tail.shiftRight(32);
        }
        byte[] tail = buf.array();
        tail[0] = (byte) ((head << 6) | (byteToUnsigned(tail[0]) >>> 2));
        return tail;
    }

    private static String shiftBase9(String s) {
        StringBuilder result = new StringBuilder(s.length());
        for (int i=0; i<s.length(); i++) {
            char c = s.charAt(i);
            if (c < '5') {
                result.append(c);
            } else {
                result.append((char) (c+1));
            }
        }
        return result.toString();
    }

    private static String unshiftBase9(String s) {
        StringBuilder result = new StringBuilder(s.length());
        for (int i=0; i<s.length(); i++) {
            char c = s.charAt(i);
            if (c < '5') {
                result.append(c);
            } else if (c == '5') {
                // ignore 5s
            } else {
                result.append((char) (c-1));
            }
        }
        return result.toString();
    }

    private static int byteToUnsigned(byte b) {
        return b & 0xFF;
    }
}
