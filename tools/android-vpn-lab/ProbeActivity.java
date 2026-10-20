package fun.loom.lab;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.Network;
import android.net.LinkProperties;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.system.ErrnoException;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** Explicit laboratory APK: API behavior only, no Rust/JNI or production VPN. */
public class ProbeActivity extends Activity {
    static synchronized void record(Context context, String key, Object value) {
        try {
            File file = new File(context.getFilesDir(), "result.json");
            JSONObject state = new JSONObject();
            if (file.isFile()) {
                try (FileInputStream in = new FileInputStream(file)) {
                    byte[] data = new byte[(int) file.length()];
                    int count = in.read(data);
                    if (count > 0) state = new JSONObject(new String(data, 0, count, StandardCharsets.UTF_8));
                }
            }
            state.put(key, value);
            File temporary = new File(context.getFilesDir(), "result.tmp");
            try (FileOutputStream out = new FileOutputStream(temporary)) {
                out.write(state.toString().getBytes(StandardCharsets.UTF_8));
                out.getFD().sync();
            }
            if (!temporary.renameTo(file)) throw new IllegalStateException("result rename failed");
            android.util.Log.i("LoomVpnLab", key + "=" + value);
        } catch (Exception error) {
            android.util.Log.e("LoomVpnLab", "cannot record result", error);
            throw new IllegalStateException(error);
        }
    }

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        new File(getFilesDir(), "result.json").delete();
        record(this, "lab_only", true);
        record(this, "uid", android.os.Process.myUid());
        record(this, "mode", getIntent().getStringExtra("mode"));
        try { verifyRustCore(); }
        catch (Exception error) {
            record(this, "error", error.toString());
            record(this, "state", "failed");
            return;
        }
        TextView text = new TextView(this);
        text.setText("Loom VPN laboratory");
        setContentView(text);
        Intent request = VpnService.prepare(this);
        record(this, "prepare_requires_consent", request != null);
        if ("denied".equals(getIntent().getStringExtra("mode"))) {
            begin();
        } else if (request != null) {
            startActivityForResult(request, 1);
        } else {
            begin();
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        record(this, "consent_result_ok", result == RESULT_OK);
        if (result == RESULT_OK) begin();
        else record(this, "state", "consent_denied");
    }

    void begin() {
        Intent service = new Intent(this, Tunnel.class);
        service.putExtras(getIntent());
        startForegroundService(service);
    }

    byte[] asset(String name) throws Exception {
        try (InputStream input = getAssets().open(name); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int length;
            while ((length = input.read(buffer)) != -1) output.write(buffer, 0, length);
            return output.toByteArray();
        }
    }

    void verifyRustCore() throws Exception {
        byte[] fixture = asset("membership.bin");
        byte[] expected = asset("membership.expected");
        long now = System.currentTimeMillis();
        Tunnel.require(Arrays.equals(expected, NativeCore.verifyMembership(fixture, now)), "Rust membership fields mismatch");
        record(this, "rust_jni_membership_verified", true);
        String[] names = {"bad_signature", "wrong_space", "stale_sequence", "expired", "truncated", "oversized"};
        for (int i = 0; i < names.length; i++) {
            byte[] invalid = fixture.clone(); long clock = now;
            if (i == 0) invalid[invalid.length - 1] ^= 1;
            if (i == 1) invalid[40] ^= 1;
            if (i == 2) invalid[191] ^= 1;
            if (i == 3) clock = Long.MAX_VALUE;
            if (i == 4) invalid = Arrays.copyOf(invalid, 259);
            if (i == 5) invalid = new byte[66001];
            boolean refused = false;
            try { NativeCore.verifyMembership(invalid, clock); }
            catch (IllegalArgumentException correct) { refused = true; }
            Tunnel.require(refused, "Rust accepted " + names[i]);
            record(this, "rust_refused_" + names[i], true);
        }
    }

    public static class Tunnel extends VpnService {
        private ParcelFileDescriptor tun;
        private DatagramSocket protectedSocket;
        private ConnectivityManager connectivity;
        private ConnectivityManager.NetworkCallback callback;
        private volatile boolean closing;

        @Override public int onStartCommand(Intent intent, int flags, int startId) {
            if (intent == null) {
                record(this, "unrequested_restart_refused", true);
                stopSelf();
                return START_NOT_STICKY;
            }
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(new NotificationChannel("loom-lab", "Loom VPN laboratory", NotificationManager.IMPORTANCE_LOW));
            startForeground(1, new Notification.Builder(this, "loom-lab")
                .setContentTitle("Loom VPN laboratory")
                .setSmallIcon(android.R.drawable.stat_sys_warning).build());
            record(this, "foreground_started", true);
            new Thread(() -> probe(intent), "loom-vpn-lab").start();
            return START_NOT_STICKY;
        }

        void probe(Intent intent) {
            String mode = intent.getStringExtra("mode");
            try {
                if ("denied".equals(mode)) {
                    boolean refused;
                    try {
                        tun = new Builder().setSession("Loom denied probe")
                            .addAddress("10.77.0.1", 32).addRoute("198.18.0.1", 32).establish();
                        refused = tun == null;
                    } catch (SecurityException expected) {
                        refused = true;
                    }
                    require(refused, "unauthorized establish succeeded");
                    record(this, "unprepared_establish_refused", true);
                    record(this, "state", "passed");
                    closeResources();
                    stopSelf();
                    return;
                }
                require(VpnService.prepare(this) == null, "VPN not prepared");
                record(this, "prepared_after_consent", true);
                String host = intent.getStringExtra("echo_host");
                int port = intent.getIntExtra("echo_port", 19999);
                InetAddress address = InetAddress.getByName(host);
                protectedSocket = new DatagramSocket();
                require(protect(protectedSocket), "protect failed");
                record(this, "protect_before_connect", true);
                protectedSocket.connect(address, port);
                protectedSocket.setSoTimeout(3000);
                connectivity = getSystemService(ConnectivityManager.class);
                CountDownLatch readyNetwork = new CountDownLatch(1);
                callback = new ConnectivityManager.NetworkCallback() {
                    private Network vpn;
                    @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpn = network;
                    }
                    @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                        if (network.equals(vpn) && properties.getInterfaceName() != null
                                && properties.getInterfaceName().startsWith("tun")) readyNetwork.countDown();
                    }
                };
                connectivity.registerDefaultNetworkCallback(callback);
                tun = new Builder().setSession("Loom isolated lab").setMtu(1500)
                    .addAddress("10.77.0.1", 32).addRoute(host, 32)
                    .addAllowedApplication(getPackageName()).setBlocking(false).establish();
                require(tun != null, "TUN establish returned null");
                record(this, "tun_established", true);
                // getActiveNetwork() can expose the VPN before netd has installed its routes.
                // Default-network callbacks are delivered after the framework declares it ready.
                require(readyNetwork.await(5, TimeUnit.SECONDS), "VPN readiness callback absent");
                record(this, "vpn_ready_callback", true);
                record(this, "vpn_network_active", true);
                if ("inspect".equals(mode)) {
                    record(this, "state", "holding_for_route_inspection");
                    while (!closing) Thread.sleep(100);
                    return;
                }
                byte[] protectedPayload = "LOOM-PROTECTED-ECHO".getBytes(StandardCharsets.US_ASCII);
                protectedSocket.send(new DatagramPacket(protectedPayload, protectedPayload.length));
                byte[] echo = new byte[256];
                DatagramPacket reply = new DatagramPacket(echo, echo.length);
                protectedSocket.receive(reply);
                require(Arrays.equals(protectedPayload, Arrays.copyOf(echo, reply.getLength())), "protected echo mismatch");
                record(this, "protected_socket_bypasses_tun", true);
                ProtectRecorder rustProtection = new ProtectRecorder(this, false);
                byte[] rustReply = NativeCore.protectedEcho(rustProtection, address.getAddress(), port, protectedPayload);
                require(Arrays.equals(protectedPayload, rustReply), "Rust protected echo mismatch");
                require(rustProtection.called && rustProtection.unconnected, "Rust protection happened after connect");
                require(socketGone(rustProtection.socketIdentity), "Rust protected socket retained");
                record(this, "rust_protect_before_connect", true);
                record(this, "rust_protected_socket_closed", true);
                ProtectRecorder refusedProtection = new ProtectRecorder(this, true);
                boolean refused = false;
                try { NativeCore.protectedEcho(refusedProtection, address.getAddress(), port, protectedPayload); }
                catch (IllegalStateException expected) { refused = true; }
                require(refused && refusedProtection.called && refusedProtection.unconnected, "Rust ignored protect failure");
                require(socketGone(refusedProtection.socketIdentity), "Rust refused socket retained");
                record(this, "rust_protect_false_refused_before_io", true);
                record(this, "rust_refused_socket_closed", true);
                byte[] canary = "LOOM-UNPROTECTED-TUN-CANARY".getBytes(StandardCharsets.US_ASCII);
                try (DatagramSocket blocked = new DatagramSocket();
                     FileInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(
                         ParcelFileDescriptor.dup(tun.getFileDescriptor()))) {
                    blocked.connect(address, port);
                    blocked.setSoTimeout(400);
                    blocked.send(new DatagramPacket(canary, canary.length));
                    StructPollfd ready = new StructPollfd();
                    ready.fd = input.getFD();
                    ready.events = (short) OsConstants.POLLIN;
                    byte[] packet = new byte[1500];
                    boolean captured = false;
                    long deadline = android.os.SystemClock.elapsedRealtime() + 3000;
                    JSONArray diagnostics = new JSONArray();
                    while (!captured && diagnostics.length() < 16 && android.os.SystemClock.elapsedRealtime() < deadline) {
                        int remaining = (int) (deadline - android.os.SystemClock.elapsedRealtime());
                        if (Os.poll(new StructPollfd[] { ready }, Math.max(1, remaining)) <= 0) break;
                        int size = input.read(packet);
                        int rustKind = NativeCore.classifyPacket(Arrays.copyOf(packet, size));
                        StringBuilder diagnostic = new StringBuilder();
                        for (int i = 0; i < Math.min(size, 96); i++) diagnostic.append(String.format("%02x", packet[i] & 255));
                        diagnostics.put(diagnostic.toString());
                        int header = (packet[0] & 15) * 4;
                        captured = rustKind == 1 && size >= header + 8 + canary.length && header >= 20
                            && (packet[0] >> 4 & 15) == 4 && packet[9] == 17
                            && Arrays.equals(address.getAddress(), Arrays.copyOfRange(packet, 16, 20))
                            && ((packet[header + 2] & 255) << 8 | packet[header + 3] & 255) == port
                            && Arrays.equals(canary, Arrays.copyOfRange(packet, header + 8, size));
                    }
                    record(this, "tun_packet_hex", diagnostics);
                    require(captured, "canary IPv4/UDP packet absent from TUN");
                    record(this, "unprotected_udp_captured_in_tun", true);
                    record(this, "rust_tun_packet_validated", true);
                    try {
                        blocked.receive(new DatagramPacket(new byte[256], 256));
                        throw new IllegalStateException("unprotected datagram leaked to echo server");
                    } catch (SocketTimeoutException expected) {
                        record(this, "unprotected_udp_echo_absent", true);
                    }
                }
                if ("hold".equals(mode)) {
                    record(this, "state", "holding");
                    while (!closing) Thread.sleep(100);
                } else {
                    closeResources();
                    record(this, "state", "passed");
                    stopSelf();
                }
            } catch (Exception error) {
                record(this, "error", error.toString());
                record(this, "state", "failed");
                closeResources();
                stopSelf();
            }
        }

        static void require(boolean condition, String message) {
            if (!condition) throw new IllegalStateException(message);
        }

        boolean socketGone(String identity) throws Exception {
            require(identity != null && identity.startsWith("socket:["), "missing Rust socket identity");
            String[] files = new File("/proc/self/fd").list();
            require(files != null, "FD inventory failed");
            for (String file : files) {
                try { if (identity.equals(Os.readlink("/proc/self/fd/" + file))) return false; }
                catch (ErrnoException closedDuringScan) {
                    if (closedDuringScan.errno != OsConstants.ENOENT) throw closedDuringScan;
                }
            }
            return true;
        }

        synchronized void closeResources() {
            closing = true;
            try {
                if (callback != null) {
                    connectivity.unregisterNetworkCallback(callback);
                    callback = null;
                }
                if (tun != null) {
                    java.io.FileDescriptor descriptor = tun.getFileDescriptor();
                    tun.close();
                    record(this, "tun_fd_closed", !descriptor.valid());
                    tun = null;
                }
                if (protectedSocket != null) {
                    protectedSocket.close();
                    record(this, "protected_socket_closed", protectedSocket.isClosed());
                }
            } catch (Exception error) {
                record(this, "cleanup_error", error.toString());
            }
        }

        @Override public void onRevoke() {
            record(this, "on_revoke", true);
            closeResources();
            record(this, "state", "revoked");
            stopSelf();
        }

        @Override public void onDestroy() {
            closeResources();
            stopForeground(STOP_FOREGROUND_REMOVE);
            record(this, "on_destroy", true);
            super.onDestroy();
        }
    }

    /** Synchronous JNI callback: borrows the Rust FD, duplicates only for the
     * unconnected check, closes the duplicate, then calls actual VpnService.protect. */
    public static class ProtectRecorder {
        private final VpnService service;
        private final boolean deny;
        boolean called, unconnected;
        String socketIdentity;
        ProtectRecorder(VpnService service, boolean deny) { this.service = service; this.deny = deny; }
        public boolean protect(int fd) throws Exception {
            called = true;
            socketIdentity = Os.readlink("/proc/self/fd/" + fd);
            try (ParcelFileDescriptor borrowed = ParcelFileDescriptor.fromFd(fd)) {
                try { Os.getpeername(borrowed.getFileDescriptor()); }
                catch (ErrnoException expected) {
                    if (expected.errno != OsConstants.ENOTCONN) throw expected;
                    unconnected = true;
                }
            }
            Tunnel.require(unconnected, "Rust connected before protection");
            return !deny && service.protect(fd);
        }
    }
}
