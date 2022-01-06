package org.whispersystems.libsignal.util;

import java.util.Arrays;

/**
 * This is a port of https://github.com/paragonie/constant_time_encoding/blob/master/src/Base32.php
 * intended to avoid cache timing attacks by avoiding the use of table lookups and branching
 * constructs. The encoding and decoding logic only use bitwise operators except for length
 * dependent logic, meaning that for inputs of a given length, encode/decode should be
 * constant-time.
 * <p>
 * This does not use padding and uses only lower case.
 */
public class NewBase32 {
    /**
     * Decode from Base32
     */
    public static byte[] decode(char[] src) {
        if (src == null) {
            return null;
        }

        int srcLen = src.length;
        if (srcLen == 0) {
            return null;
        }

        int err = 0;
        ByteArrayBuilder dest = new ByteArrayBuilder(srcLen * 5 / 8);
        // Main loop
        int i;
        for (i = 0; i + 8 <= srcLen; i += 8) {
            char[] chunk = Arrays.copyOfRange(src, i, Math.min(srcLen, i + 8));
            int c0 = decode5Bits(chunk[0]);
            int c1 = decode5Bits(chunk[1]);
            int c2 = decode5Bits(chunk[2]);
            int c3 = decode5Bits(chunk[3]);
            int c4 = decode5Bits(chunk[4]);
            int c5 = decode5Bits(chunk[5]);
            int c6 = decode5Bits(chunk[6]);
            int c7 = decode5Bits(chunk[7]);

            dest.append(
                    ((c0 << 3) | (c1 >> 2)) & 255,
                    ((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 255,
                    ((c3 << 4) | (c4 >> 1)) & 255,
                    ((c4 << 7) | (c5 << 2) | (c6 >> 3)) & 255,
                    ((c6 << 5) | (c7)) & 255
            );
            err |= (c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7) >> 8;
        }
        // The last chunk
        if (i < srcLen) {
            char[] chunk = Arrays.copyOfRange(src, i, srcLen);
            int c0 = decode5Bits(chunk[0]);

            if (i + 6 < srcLen) {
                int c1 = decode5Bits(chunk[1]);
                int c2 = decode5Bits(chunk[2]);
                int c3 = decode5Bits(chunk[3]);
                int c4 = decode5Bits(chunk[4]);
                int c5 = decode5Bits(chunk[5]);
                int c6 = decode5Bits(chunk[6]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255,
                        ((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 255,
                        ((c3 << 4) | (c4 >> 1)) & 255,
                        ((c4 << 7) | (c5 << 2) | (c6 >> 3)) & 255
                );
                err |= (c0 | c1 | c2 | c3 | c4 | c5 | c6) >> 8;
            } else if (i + 5 < srcLen) {
                int c1 = decode5Bits(chunk[1]);
                int c2 = decode5Bits(chunk[2]);
                int c3 = decode5Bits(chunk[3]);
                int c4 = decode5Bits(chunk[4]);
                int c5 = decode5Bits(chunk[5]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255,
                        ((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 255,
                        ((c3 << 4) | (c4 >> 1)) & 255,
                        ((c4 << 7) | (c5 << 2)) & 255
                );
                err |= (c0 | c1 | c2 | c3 | c4 | c5) >> 8;
            } else if (i + 4 < srcLen) {
                int c1 = decode5Bits(chunk[1]);
                int c2 = decode5Bits(chunk[2]);
                int c3 = decode5Bits(chunk[3]);
                int c4 = decode5Bits(chunk[4]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255,
                        ((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 255,
                        ((c3 << 4) | (c4 >> 1)) & 255
                );
                err |= (c0 | c1 | c2 | c3 | c4) >> 8;
            } else if (i + 3 < srcLen) {
                int c1 = decode5Bits(chunk[1]);
                int c2 = decode5Bits(chunk[2]);
                int c3 = decode5Bits(chunk[3]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255,
                        ((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 255
                );
                err |= (c0 | c1 | c2 | c3) >> 8;
            } else if (i + 2 < srcLen) {
                int c1 = decode5Bits(chunk[1]);
                int c2 = decode5Bits(chunk[2]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255,
                        ((c1 << 6) | (c2 << 1)) & 255
                );
                err |= (c0 | c1 | c2) >> 8;
            } else if (i + 1 < srcLen) {
                int c1 = decode5Bits(chunk[1]);

                dest.append(((c0 << 3) | (c1 >> 2)) & 255
                );
                err |= (c0 | c1) >> 8;
            } else {
                dest.append(((c0 << 3)) & 255
                );
                err |= (c0) >> 8;
            }
        }
        boolean check = (err == 0);
        if (!check) {
            throw new InvalidCharacterException();
        }
        return dest.b;
    }

    /**
     * Encode to Base32
     */
    public static char[] encode(byte[] src) {
        int srcLen = src.length;
        CharArrayBuilder dest = new CharArrayBuilder((int) Math.ceil(srcLen * 8.0 / 5.0));

        int i;
        // Main loop
        for (i = 0; i + 5 <= srcLen; i += 5) {
            byte[] chunk = Arrays.copyOfRange(src, i, Math.min(srcLen, i + 5));
            int b0 = byteToInt(chunk[0]);
            int b1 = byteToInt(chunk[1]);
            int b2 = byteToInt(chunk[2]);
            int b3 = byteToInt(chunk[3]);
            int b4 = byteToInt(chunk[4]);
            dest.append(
                    encode5Bits((b0 >> 3) & 31),
                    encode5Bits(((b0 << 2) | (b1 >> 6)) & 31),
                    encode5Bits(((b1 >> 1)) & 31),
                    encode5Bits(((b1 << 4) | (b2 >> 4)) & 31),
                    encode5Bits(((b2 << 1) | (b3 >> 7)) & 31),
                    encode5Bits(((b3 >> 2)) & 31),
                    encode5Bits(((b3 << 3) | (b4 >> 5)) & 31),
                    encode5Bits(b4 & 31));
        }
        // The last chunk, which may have padding:
        if (i < srcLen) {
            byte[] chunk = Arrays.copyOfRange(src, i, srcLen);
            int b0 = byteToInt(chunk[0]);
            if (i + 3 < srcLen) {
                int b1 = byteToInt(chunk[1]);
                int b2 = byteToInt(chunk[2]);
                int b3 = byteToInt(chunk[3]);
                dest.append(
                        encode5Bits((b0 >> 3) & 31),
                        encode5Bits(((b0 << 2) | (b1 >> 6)) & 31),
                        encode5Bits(((b1 >> 1)) & 31),
                        encode5Bits(((b1 << 4) | (b2 >> 4)) & 31),
                        encode5Bits(((b2 << 1) | (b3 >> 7)) & 31),
                        encode5Bits(((b3 >> 2)) & 31),
                        encode5Bits(((b3 << 3)) & 31));
            } else if (i + 2 < srcLen) {
                int b1 = byteToInt(chunk[1]);
                int b2 = byteToInt(chunk[2]);
                dest.append(
                        encode5Bits((b0 >> 3) & 31),
                        encode5Bits(((b0 << 2) | (b1 >> 6)) & 31),
                        encode5Bits(((b1 >> 1)) & 31),
                        encode5Bits(((b1 << 4) | (b2 >> 4)) & 31),
                        encode5Bits(((b2 << 1)) & 31));
            } else if (i + 1 < srcLen) {
                int b1 = byteToInt(chunk[1]);
                dest.append(
                        encode5Bits((b0 >> 3) & 31),
                        encode5Bits(((b0 << 2) | (b1 >> 6)) & 31),
                        encode5Bits(((b1 >> 1)) & 31),
                        encode5Bits(((b1 << 4)) & 31));
            } else {
                dest.append(
                        encode5Bits((b0 >> 3) & 31),
                        encode5Bits((b0 << 2) & 31));
            }
        }
        return dest.c;
    }

    /**
     * Uses bitwise operators instead of table-lookups to turn 5-bit integers
     * into 8-bit integers.
     */
    private static int decode5Bits(int in) {
        int out = -1;

        // if (in > 96 && in < 123) out += in - 97 + 1; // -64
        out += (((96 - in) & (in - 123)) >> 8) & (in - 96);

        // if (in > 49 && in < 56) out += in - 24 + 1; // -23
        out += (((49 - in) & (in - 56)) >> 8) & (in - 23);

        return out;
    }

    /**
     * Uses bitwise operators instead of table-lookups to turn 8-bit integers
     * into 5-bit integers.
     */
    private static char encode5Bits(int in) {
        int diff = 97; // ASCII lowercase a

        // if (in > 25) ret -= 72 (shifts from alphas to numbers)
        diff -= ((25 - in) >> 8) & 73;

        return (char) (in + diff);
    }

    /**
     * Shift negative bytes into positive ints so that they work like unsigned bytes/ints.
     */
    private static int byteToInt(byte b) {
        int i = b;

        // shift negative bytes to positive ints if necessary
        i += (i >> 8) & 256;

        return i;
    }

    private static class ByteArrayBuilder {
        private final byte[] b;
        private int i = 0;

        private ByteArrayBuilder(int length) {
            b = new byte[length];
        }

        private void append(int... values) {
            for (int v : values) {
                b[i] = (byte) v;
                i++;
            }
        }
    }

    private static class CharArrayBuilder {
        private final char[] c;
        private int i = 0;

        private CharArrayBuilder(int length) {
            c = new char[length];
        }

        private void append(int... values) {
            for (int v : values) {
                c[i] = (char) v;
                i++;
            }
        }
    }
}
