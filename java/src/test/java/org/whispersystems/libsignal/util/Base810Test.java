package org.whispersystems.libsignal.util;

import junit.framework.TestCase;

import java.util.Random;

public class Base810Test extends TestCase {
    public void testEncodeToString() {
        final byte[] b = Base32.humanFriendly.decodeFromString(
                "rfu2495fqazzpq1e3xkj1skmr9785hwbxggpr17ut1htj4h9nhyy"
        );
        assertEquals(
                "3003801133333346943057816173883590383104318198846436715594769652093018596906752",
                Base810.encodeToString(b, 79)
        );
    }

    public void testRoundTrip() {
        final Random random = new Random();
        for (int i = 0; i < 10000; i++) {
            byte[] b = new byte[32];
            random.nextBytes(b);
            String expected = Base810.encodeToString(b, 79);
            String actual = Base810.encodeToString(Base810.decodeFromString(expected, 32), 79);
            assertEquals(expected, actual);
        }
    }
}
