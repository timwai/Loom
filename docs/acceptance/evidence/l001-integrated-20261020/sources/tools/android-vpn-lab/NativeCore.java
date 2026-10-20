package fun.loom.lab;

/** Narrow Rust credential/packet boundary; no production VPN forwarding. */
public final class NativeCore {
    static { System.loadLibrary("loom_android"); }
    private NativeCore() {}
    public static native byte[] verifyMembership(byte[] envelope, long nowMs);
    public static native int classifyPacket(byte[] packet);
    public static native byte[] protectedEcho(Object protector, byte[] address, int port, byte[] payload);
}
