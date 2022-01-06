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
 * <p>
 * This uses the alphabet ybndrfg8ejkmcpqxot1uw2sza345h769, which is similar to the z-base-32
 * alphabet that preferences characters that are easier for humans to read, but our alphabet omits
 * the number 0 and the letters i, l and v. On decoding, it also maps the letters i and l to the
 * number 1 and the number 0 to the letter o.
 */
public class Base32 {
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
     * into 8-bit integers. This is based on a custom alphabet similar to z-base-32, and is the
     * inverse of what encode5Bits does.
     */
    private static int decode5Bits(int in) {
        // replace i with 1
        in = replaceCharacter(in, 105, 49);

        // replace l with 1
        in = replaceCharacter(in, 108, 49);

        // replace 0 with o
        in = replaceCharacter(in, 48, 111);

        int out = 18; // 1
        out += ((49 - in) >> 8) & 3; // 1 -> 2
        out += ((50 - in) >> 8) & 4; // 2 -> 3
        out += ((51 - in) >> 8) & 1; // 3 -> 4
        out += ((52 - in) >> 8) & 1; // 4 -> 5
        out += ((53 - in) >> 8) & 3; // 5 -> 6
        out -= ((54 - in) >> 8) & 1; // 6 -> 7
        out -= ((55 - in) >> 8) & 22; // 7 -> 8
        out += ((56 - in) >> 8) & 24; // 8 -> 9
        out -= ((96 - in) >> 8) & 7; // 9 -> a
        out -= ((97 - in) >> 8) & 23; // a -> b
        out += ((98 - in) >> 8) & 11; // b -> c
        out -= ((99 - in) >> 8) & 9; // c -> d
        out += ((100 - in) >> 8) & 5; // d -> e
        out -= ((101 - in) >> 8) & 3; // e -> f
        out += ((102 - in) >> 8) & 1; // f -> g
        out += ((103 - in) >> 8) & 22; // g -> h
        out -= ((105 - in) >> 8) & 19; // h -> j
        out += ((106 - in) >> 8) & 1; // j -> k
        out += ((108 - in) >> 8) & 1; // k -> m
        out -= ((109 - in) >> 8) & 9; // m -> n
        out += ((110 - in) >> 8) & 14; // n -> o
        out -= ((111 - in) >> 8) & 3; // o -> p
        out += ((112 - in) >> 8) & 1; // p -> q
        out -= ((113 - in) >> 8) & 10; // q -> r
        out += ((114 - in) >> 8) & 18; // r -> s
        out -= ((115 - in) >> 8) & 5; // s -> t
        out += ((116 - in) >> 8) & 2; // t -> u
        out += ((118 - in) >> 8) & 1; // u -> w
        out -= ((119 - in) >> 8) & 5; // w -> x
        out -= ((120 - in) >> 8) & 15; // x -> y
        out += ((121 - in) >> 8) & 23; // y -> z
        return out;
    }

    /**
     * Replaces actual with replacement if actual == expected, using bitwise operators for
     * constant-time evaluation.
     */
    private static int replaceCharacter(int actual, int expected, int replacement) {
        int diff = replacement - expected;
        int result = actual;
        result += (((expected - 1 - actual) & (actual - expected - 1)) >> 8) & diff;
        return result;
    }

    /**
     * Uses bitwise operators instead of table-lookups to turn 8-bit integers
     * into 5-bit integers. This implements a constant time version of a custom human-friendly
     * alphabet based on the z-base-32 character map. The algorithm jumps from character to
     * character until it reaches the correct character for the input value.
     * <p>
     * Examples:
     * <p>
     * 0: stay at y
     * 1: jump y -> b
     * 5: y -> b -> n -> d -> r -> f
     */
    private static char encode5Bits(int in) {
        int out = 121; // y
        out -= ((0 - in) >> 8) & 23; // y -> b
        out += ((1 - in) >> 8) & 12; // b -> n
        out -= ((2 - in) >> 8) & 10; // n -> d
        out += ((3 - in) >> 8) & 14; // d -> r
        out -= ((4 - in) >> 8) & 12; // r -> f
        out += ((5 - in) >> 8) & 1; // f -> g
        out -= ((6 - in) >> 8) & 47; // g -> 8
        out += ((7 - in) >> 8) & 45; // 8 -> e
        out += ((8 - in) >> 8) & 5; // e -> j
        out += ((9 - in) >> 8) & 1; // j -> k
        out += ((10 - in) >> 8) & 2; // k -> m
        out -= ((11 - in) >> 8) & 10; // m -> c
        out += ((12 - in) >> 8) & 13; // c -> p
        out += ((13 - in) >> 8) & 1; // p -> q
        out += ((14 - in) >> 8) & 7; // q -> x
        out -= ((15 - in) >> 8) & 9; // x -> o
        out += ((16 - in) >> 8) & 5; // o -> t
        out -= ((17 - in) >> 8) & 67; // t -> 1
        out += ((18 - in) >> 8) & 68; // 1 -> u
        out += ((19 - in) >> 8) & 2; // u -> w
        out -= ((20 - in) >> 8) & 69; // w -> 2
        out += ((21 - in) >> 8) & 65; // 2 -> s
        out += ((22 - in) >> 8) & 7; // s -> z
        out -= ((23 - in) >> 8) & 25; // z -> a
        out -= ((24 - in) >> 8) & 46; // a -> 3
        out += ((25 - in) >> 8) & 1; // 3 -> 4
        out += ((26 - in) >> 8) & 1; // 4 -> 5
        out += ((27 - in) >> 8) & 51; // 5 -> h
        out -= ((28 - in) >> 8) & 49; // h -> 7
        out -= ((29 - in) >> 8) & 1; // 7 -> 6
        out += ((30 - in) >> 8) & 3; // 6 -> 9
        return (char) out;
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
                if (i >= b.length) {
                    throw new InvalidCharacterException();
                }
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
