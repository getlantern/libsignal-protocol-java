package org.whispersystems.libsignal.util;

/**
 * Indicates an attempt to Base32 decode a string with an invalid character.
 */
public class InvalidCharacterException extends RuntimeException {
    public InvalidCharacterException() {
        super("Base32.decode() only expects characters in the correct base32 alphabet");
    }
}
