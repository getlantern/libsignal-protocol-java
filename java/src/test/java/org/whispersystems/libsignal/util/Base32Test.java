package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Base32Test extends TestCase {
    public void testRoundTripString() {
        for (int i = 1; i < 128; i++) {
            StringBuilder builder = new StringBuilder(i);
            for (int j = 0; j < i; j++) {
                builder.append(j);
            }
            String string = builder.toString();
            char[] encoded = Base32.encode(string.getBytes(StandardCharsets.UTF_8));
            System.out.println(new String(encoded));
            String roundTripped = new String(Base32.decode(encoded));
            assertEquals(string, roundTripped);
        }
    }

    public void testRoundTripBytes() {
        byte[] b = new byte[0];
        for (int i = 0; i < 255; i++) {
            b = Arrays.copyOf(b, b.length + 1);
            b[i] = (byte) i;
            char[] encoded = Base32.encode(b);
            System.out.println(new String(encoded));
            byte[] roundTripped = Base32.decode(encoded);
            assertTrue(Arrays.equals(b, roundTripped));
        }
    }

    public void testDecodeSpecialCharacters() {
        String normal = "y100";
        assertEquals(
                new String(Base32.decode(normal.toCharArray())),
                new String(Base32.decode("yi00".toCharArray()))
        );
        assertEquals(
                new String(Base32.decode(normal.toCharArray())),
                new String(Base32.decode("yl00".toCharArray()))
        );
        assertEquals(
                new String(Base32.decode(normal.toCharArray())),
                new String(Base32.decode("y1oo".toCharArray()))
        );
    }
}
