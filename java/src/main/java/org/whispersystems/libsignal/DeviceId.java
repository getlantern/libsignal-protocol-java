package org.whispersystems.libsignal;

import org.whispersystems.libsignal.util.Base32;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

public class DeviceId {
    private final byte[] bytes;

    public DeviceId(byte[] bytes) {
        this.bytes = bytes;
    }

    public DeviceId(String humanFriendlyString) {
        this(Base32.humanFriendly.decodeFromString(humanFriendlyString));
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static DeviceId random() {
        return new DeviceId(toBytes(UUID.randomUUID()));
    }

    private static byte[] toBytes(UUID uuid) {
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    public String toString() {
        return Base32.humanFriendly.encodeToString(bytes);
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
