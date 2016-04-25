package org.openvpp.jvpp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import org.openvpp.jvpp.callback.JVppCallback;

public final class VppJNIConnection implements VppConnection {
    private static final String LIBNAME = "libjvpp.so.0.0.0";

    static {
        try {
            loadLibrary();
        } catch (Exception e) {
            System.err.printf("Can't find vpp jni library: %s\n", LIBNAME);
            throw new ExceptionInInitializerError(e);
        }
    }

    private static void loadStream(final InputStream is) throws IOException {
        final Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxr-x---");
        final Path p = Files.createTempFile(LIBNAME, null, PosixFilePermissions.asFileAttribute(perms));
        try {
            Files.copy(is, p, StandardCopyOption.REPLACE_EXISTING);

            try {
                Runtime.getRuntime().load(p.toString());
            } catch (UnsatisfiedLinkError e) {
                throw new IOException(String.format("Failed to load library %s", p), e);
            }
        } finally {
            try {
                Files.deleteIfExists(p);
            } catch (IOException e) {
            }
        }
    }

    private static void loadLibrary() throws IOException {
        try (final InputStream is = VppJNIConnection.class.getResourceAsStream('/' + LIBNAME)) {
            if (is == null) {
                throw new IOException(String.format("Failed to open library resource %s",
                        LIBNAME));
            }
            loadStream(is);
        }
    }

    private static VppJNIConnection currentConnection = null;
    private final String clientName;
    private volatile boolean disconnected = false;

    public VppJNIConnection(final String clientName, final JVppCallback callback) throws IOException {
        this.clientName = clientName;

        synchronized (VppJNIConnection.class) {
            if (currentConnection != null) {
                throw new IOException("Already connected as " + currentConnection.clientName);
            }

            final int ret = clientConnect(clientName, callback);
            if (ret != 0) {
                throw new IOException("Connection returned error " + ret);
            }

            currentConnection = this;
        }
    }


    @Override
    public final void checkActive() {
        if (disconnected) {
            throw new IllegalStateException("Disconnected client " + clientName);
        }
    }

    @Override
    public synchronized final void close() {
        if (!disconnected) {
            disconnected = true;

            synchronized (VppJNIConnection.class) {
                clientDisconnect();
                currentConnection = null;
            }
        }
    }

    private static native int clientConnect(String clientName, JVppCallback callback);
    private static native void clientDisconnect();
}
