/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openvpp.jvpp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.openvpp.jvpp.callback.JVppCallback;

/**
 * JNI based representation of a management connection to VPP
 */
public final class VppJNIConnection implements VppConnection {
    private final static Logger LOG = Logger.getLogger(VppJNIConnection.class.getName());
    private static final String LIBNAME = "libjvpp.so.0.0.0";

    static {
        try {
            loadLibrary();
        } catch (Exception e) {
            LOG.severe("Can't find vpp jni library: " + LIBNAME);
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
                throw new IOException("Failed to load library " + p, e);
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
                throw new IOException("Failed to open library resource " + LIBNAME);
            }
            loadStream(is);
        }
    }

    private final String clientName;
    private volatile boolean disconnected = false;

    private VppJNIConnection(final String clientName) {
        if (clientName == null) {
            throw new NullPointerException("Null clientName");
        }
        this.clientName = clientName;
    }

    /**
     * Guarded by VppJNIConnection.class
     */
    private static final Map<String, VppJNIConnection> connections = new HashMap<>();

    /**
     * Create a new Vpp connection identified by clientName parameter.
     *
     * Multiple instances are allowed since this class is not a singleton
     * (VPP allows multiple management connections).
     *
     * However only a single connection per clientName is allowed.
     *
     * @param clientName identifier of vpp connection
     * @param callback global callback to receive response calls from vpp
     *
     * @return new Vpp connection
     * @throws IOException in case the connection could not be established, or there already is a connection with the same name
     */
    public static VppJNIConnection create(final String clientName, final JVppCallback callback) throws IOException {
        synchronized (VppJNIConnection.class) {
            if(connections.containsKey(clientName)) {
                throw new IOException("Client " + clientName + " already connected");
            }

            final VppJNIConnection vppJNIConnection = new VppJNIConnection(clientName);
            final int ret = clientConnect(clientName, callback);
            if (ret != 0) {
                throw new IOException("Connection returned error " + ret);
            }
            connections.put(clientName, vppJNIConnection);
            return vppJNIConnection;
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
            try {
                clientDisconnect();
            } finally {
                synchronized (VppJNIConnection.class) {
                    connections.remove(clientName);
                }
            }
        }
    }

    private static native int clientConnect(String clientName, JVppCallback callback);
    private static native void clientDisconnect();
}
