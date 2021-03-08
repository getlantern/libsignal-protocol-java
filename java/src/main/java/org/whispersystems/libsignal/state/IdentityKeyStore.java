/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.whispersystems.libsignal.ecc.ECKeyPair;

/**
 * Provides an interface to identity information.
 *
 * @author Moxie Marlinspike
 */
public interface IdentityKeyStore {

    public enum Direction {
        SENDING, RECEIVING
    }

    /**
     * Get the local client's identity key pair.
     *
     * @return The local client's persistent identity key pair.
     */
    public ECKeyPair getIdentityKeyPair();
}
