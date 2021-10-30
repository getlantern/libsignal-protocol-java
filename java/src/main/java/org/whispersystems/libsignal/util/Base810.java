package org.whispersystems.libsignal.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides a human-friendly encoding that looks like a phone number but isn't usually a dialable
 * phone number, because it doesn't start with 0 or 1 (as is required in most countries). This
 * encoding treats a byte array as a big-endian number. The first (most significant) 3 bits of data
 * are encoded using a shifted octal encoding (digits 2-9 instead of the standard 0-7) and the
 * remaining data is encoded in base10 and left-padded with '0's to meet the desired length.
 */
public class Base810 {
    private static final Map<Byte, Character> base8Table = new HashMap<>();
    private static final Map<Character, Byte> base8TableReverse = new HashMap<>();

    static {
        addMapping((byte) 0, '2');
        addMapping((byte) 1, '3');
        addMapping((byte) 2, '4');
        addMapping((byte) 3, '5');
        addMapping((byte) -4, '6');
        addMapping((byte) -3, '7');
        addMapping((byte) -2, '8');
        addMapping((byte) -1, '9');
    }

    private static void addMapping(final Byte b, final Character c) {
        base8Table.put(b, c);
        base8TableReverse.put(c, b);
    }

    /**
     * Encodes the given bytes using Base810 encoding. The resulting string will be of target length
     * using '0's after the first digit in order to pad up to the targetLength.
     *
     * @param b
     * @param targetLength
     * @return
     */
    public static String encodeToString(final byte[] b, final int targetLength) {
        byte[] _b = ByteUtil.copyFrom(b);
        byte head = (byte) (_b[0] >>> 5);
        _b[0] = (byte) (byteToUnsigned(_b[0]) << 3);
        String tail = new BigInteger(1, _b).toString();
        StringBuilder result = new StringBuilder(79);
        result.append(base8Table.get(head));
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
     * Decodes the given Base810 string into a byte[] of targetSize. If the string doesn't contain
     * enough data to fill targetSize, the byte[] will contain leading zeros.
     *
     * @param s
     * @param targetSize
     * @return
     */
    public static byte[] decodeFromString(final String s, final int targetSize) {
        byte head = base8TableReverse.get(s.charAt(0));
        BigInteger _tail = new BigInteger(s.substring(1), 10);
        ByteBuffer buf = ByteBuffer.allocate(targetSize);
        for (int i = targetSize / 4 - 1; i >= 0; i--) {
            buf.putInt(i * 4, _tail.intValue());
            _tail = _tail.shiftRight(32);
        }
        byte[] tail = buf.array();
        tail[0] = (byte) ((head << 5) | (byteToUnsigned(tail[0]) >>> 3));
        return tail;
    }

    private static int byteToUnsigned(byte b) {
        return b & 0xFF;
    }
}
