package org.whispersystems.libsignal.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of Base32 encoding/decoding that accepts arbitrary alphabets.
 * From http://www.herongyang.com/Encoding/Base32-Bitpedia-Java-Implementation.html;
 * <p>
 * It also supports a replacement table on decoding to handle mis-entered letters.
 */
public class Base32 {
    private static char padding = '=';
    private static String paddingString = "=";

    private final Map<Character, Character> replacements;
    private final Base32Encoder encoder;

    /**
     * Constructs a new non-padded Base32 encoder with a custom alphabet (must be 32 characters).
     * <p>
     * Based on http://www.herongyang.com/Encoding/Base32-Bitpedia-Java-Implementation.html.
     *
     * @param alphabet
     */
    public Base32(String alphabet, Map<Character, Character> replacements) {
        if (alphabet.length() != 32) {
            throw new RuntimeException("alphabet is not 32-bytes long");
        }
        this.replacements = replacements;
        encoder = new Base32Encoder(alphabet.getBytes(Charset.forName("ASCII")), (byte) padding);
    }

    /**
     * Encodes byte array to Base32 String.
     *
     * @param bytes Bytes to encode.
     * @return Encoded byte array <code>bytes</code> as a String.
     */
    public String encodeToString(final byte[] bytes) {
        int length = bytes.length;
        int encodedLength = encoder.getEncodedLength(length);
        ByteArrayOutputStream out = new ByteArrayOutputStream(encodedLength);
        try {
            encoder.encode(bytes, 0, length, out);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        try {
            // Removing padding is not constant time and leaks information about the length of a
            // value.
            return out.toString("ASCII").replace(paddingString, "");
        } catch (UnsupportedEncodingException ue) {
            throw new RuntimeException(ue);
        }
    }

    /**
     * Decodes the given Base32 String to a raw byte array.
     *
     * @param base32
     * @return Decoded <code>base32</code> String as a raw byte array.
     */
    public byte[] decodeFromString(final String base32) {
        int encodedLength = base32.length();
        int paddedLength = (int) Math.ceil(((double) encodedLength) / 8.0) * 8;
        final StringBuilder base32Builder = new StringBuilder(paddedLength);
        for (char c : base32.toCharArray()) {
            // This is not constant time, but it only applies if people have manually fat-fingered
            // a character.
            Character c2 = replacements.get(c);
            if (c2 == null) {
                c2 = c;
            }
            base32Builder.append(c2);
        }
        int requiredPadding = paddedLength - encodedLength;
        for (int i = 0; i < requiredPadding; i++) {
            // This is not constant time and leaks information about the length of a value.
            base32Builder.append(padding);
        }
        final String modified = base32Builder.toString();
        int length = modified.length() / 8 * 5;
        ByteArrayOutputStream out = new ByteArrayOutputStream(length);
        try {
            encoder.decode(modified, out);
            return out.toByteArray();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    // This alphabet is based on the z-base-32 alphabet which preferences characters that are easier
    // for humans to read. It omits the number 0 and the letters i, l and v. On decoding, we also
    // map the letters i and l to the number 1 and the number 0 to the letter o.
    private static final String humanFriendlyAlphabet = "ybndrfg8ejkmcpqxot1uw2sza345h769";
    private static final Map<Character, Character> humanFriendlyReplacements = new HashMap<>();

    static {
        // map some commonly fat-fingered characters to their correct replacements
        humanFriendlyReplacements.put('i', '1');
        humanFriendlyReplacements.put('l', '1');
        humanFriendlyReplacements.put('0', 'o');
    }

    public static final Base32 humanFriendly =
            new Base32(humanFriendlyAlphabet, humanFriendlyReplacements);
}
