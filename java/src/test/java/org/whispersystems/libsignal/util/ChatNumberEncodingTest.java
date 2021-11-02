package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import java.util.Random;

public class ChatNumberEncodingTest extends TestCase {
    public void testEncodeToString() {
        final byte[] b = Base32.humanFriendly.decodeFromString(
                "rfu2495fqazzpq1e3xkj1skmr9785hwbxggpr17ut1htj4h9nhyy"
        );
        assertEquals(
                "2277029271600308397119018701998194490680040839333862997699030902896411310611021743",
                ChatNumberEncoding.encodeToString(b, 82)
        );
    }

    public void testRoundTrip() {
        final Random random = new Random();
        for (int i = 0; i < 10000; i++) {
            byte[] b = new byte[32];
            random.nextBytes(b);
            String expected = ChatNumberEncoding.encodeToString(b, 82);
            String actual = ChatNumberEncoding.encodeToString(ChatNumberEncoding.decodeFromString(expected, 32), 82);
            assertEquals(expected, actual);
        }
    }
}
