/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import java.util.Objects;

public class SignalProtocolAddress {

    private final UserId userId;
    private final DeviceId deviceId;

    public SignalProtocolAddress(UserId userId, DeviceId deviceId) {
        this.userId = userId;
        this.deviceId = deviceId;
    }

    public SignalProtocolAddress(String userId, int deviceId) {
        this(new UserId(userId), new DeviceId(deviceId));
    }

    public UserId getUserId() {
        return userId;
    }

    public DeviceId getDeviceId() {
        return deviceId;
    }

    @Override
    public String toString() {
        return userId.toString() + ":" + deviceId.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignalProtocolAddress that = (SignalProtocolAddress) o;
        return userId.equals(that.userId) &&
                deviceId.equals(that.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, deviceId);
    }
}
