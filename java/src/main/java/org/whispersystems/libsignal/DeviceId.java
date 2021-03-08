package org.whispersystems.libsignal;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

public class DeviceId {
    private final byte[] bytes;

    public DeviceId(byte[] bytes) {
        this.bytes = bytes;
    }

    public DeviceId(UUID uuid) {
        this(toBytes(uuid));
    }

    public DeviceId(String string) {
        this(UUID.fromString(string));
    }

    public DeviceId(int deviceId) {
        this(new UUID(deviceId, 0));
    }

    public UUID toUUID() {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long firstLong = bb.getLong();
        long secondLong = bb.getLong();
        return new UUID(firstLong, secondLong);
    }

    public static DeviceId random() {
        return new DeviceId(UUID.randomUUID());
    }

    private static byte[] toBytes(UUID uuid) {
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    public String toString() {
        return toUUID().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeviceId deviceId = (DeviceId) o;
        return Arrays.equals(bytes, deviceId.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
