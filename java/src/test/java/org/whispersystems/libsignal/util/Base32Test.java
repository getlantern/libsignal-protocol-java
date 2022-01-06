package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.InvalidCharacterException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class Base32Test extends TestCase {
    public void testRoundTripString() {
        for (int i = 1; i < 128; i++) {
            StringBuilder builder = new StringBuilder(i);
            for (int j = 0; j < i; j++) {
                builder.append(j);
            }
            String string = builder.toString();
            char[] encoded = NewBase32.encode(string.getBytes(StandardCharsets.UTF_8));
            System.out.println(new String(encoded));
            String roundTripped = new String(NewBase32.decode(encoded));
            assertEquals(string, roundTripped);
        }
    }

    public void testRoundTripBytes() {
        byte[] b = new byte[0];
        for (int i = 0; i < 255; i++) {
            b = Arrays.copyOf(b, b.length + 1);
            b[i] = (byte) i;
            char[] encoded = NewBase32.encode(b);
            System.out.println(new String(encoded));
            byte[] roundTripped = NewBase32.decode(encoded);
            assertTrue(Arrays.equals(b, roundTripped));
        }
    }
}
