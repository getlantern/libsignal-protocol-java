/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.Objects;

/**
 * A SignalProtocolAddress uniquely identifies a sender or recipient in a message xchange.
 * It consists of an identity that uniquely identifies a person/organization/etc (whoever is authorized
 * to send and receive messages) and a deviceId that uniquely identifies a specific device being
 * used by that identity.
 */
public class SignalProtocolAddress {

    private final ECPublicKey identityKey;
    private final DeviceId deviceId;

    public SignalProtocolAddress(ECPublicKey identityKey, DeviceId deviceId) {
        this.identityKey = identityKey;
        this.deviceId = deviceId;
    }

    public SignalProtocolAddress(String str) throws InvalidAddressException, InvalidKeyException {
        String[] parts = str.split(":");
        if (parts.length != 2) {
            throw new InvalidAddressException("Wrong number of parts in string encoded address");
        }
        this.identityKey = new ECPublicKey(parts[0]);
        this.deviceId = new DeviceId(parts[1]);
    }

    public ECPublicKey getIdentityKey() {
        return identityKey;
    }

    public DeviceId getDeviceId() {
        return deviceId;
    }

    @Override
    public String toString() {
        return identityKey.toString() + ":" + deviceId.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignalProtocolAddress that = (SignalProtocolAddress) o;
        return identityKey.equals(that.identityKey) &&
                deviceId.equals(that.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identityKey, deviceId);
    }
}
