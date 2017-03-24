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

package io.fd.vpp.jvpp;

import static io.fd.vpp.jvpp.NativeLibraryLoader.loadLibrary;
import static java.lang.String.format;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JNI based representation of a management connection to VPP.
 */
public final class VppJNIConnection implements VppConnection {
    private static final Logger LOG = Logger.getLogger(VppJNIConnection.class.getName());
    private static final String DEFAULT_SHM_PREFIX = "/vpe-api";

    static {
        final String libName = "libjvpp_registry.so";
        try {
            loadLibrary(libName, VppJNIConnection.class);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, format("Can't find vpp jni library: %s", libName), e);
            throw new ExceptionInInitializerError(e);
        }
    }

    private ConnectionInfo connectionInfo;

    private final String clientName;
    private final String shmPrefix;
    private volatile boolean disconnected = false;

    /**
     * Create VPPJNIConnection instance for client connecting to VPP.
     *
     * @param clientName client name instance to be used for communication. Single connection per clientName is
     *                   allowed.
     */
    public VppJNIConnection(final String clientName) {
        this.clientName = Objects.requireNonNull(clientName, "Null clientName");
        this.shmPrefix = DEFAULT_SHM_PREFIX;
    }

    public VppJNIConnection(final String clientName, final String shmPrefix) {
        this.clientName = Objects.requireNonNull(clientName, "Null clientName");
        this.shmPrefix = Objects.requireNonNull(shmPrefix, "Null shmPrefix");
    }

    /**
     * Guarded by VppJNIConnection.class
     */
    private static final Map<String, VppJNIConnection> connections = new HashMap<>();

    /**
     * Initiate VPP connection for current instance
     *
     * Multiple instances are allowed since this class is not a singleton (VPP allows multiple management connections).
     *
     * However only a single connection per clientName is allowed.
     *
     * @throws IOException in case the connection could not be established
     */

    @Override
    public void connect() throws IOException {
        _connect(shmPrefix);
    }

    private void _connect(final String shmPrefix) throws IOException {
        Objects.requireNonNull(shmPrefix, "Shared memory prefix must be defined");

        synchronized (VppJNIConnection.class) {
            if (connections.containsKey(clientName)) {
                throw new IOException("Client " + clientName + " already connected");
            }

            connectionInfo = clientConnect(shmPrefix, clientName);
            if (connectionInfo.status != 0) {
                throw new IOException("Connection returned error " + connectionInfo.status);
            }
            connections.put(clientName, this);
        }
    }

    @Override
    public final void checkActive() {
        if (disconnected) {
            throw new IllegalStateException("Disconnected client " + clientName);
        }
    }

    @Override
    public final synchronized void close() {
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

    public ConnectionInfo getConnectionInfo() {
        return connectionInfo;
    }

    /**
     * VPP connection information used by plugins to reuse the connection.
     */
    public static final class ConnectionInfo {
        public final long queueAddress;
        public final int clientIndex;
        public final int status; // FIXME throw exception instead

        public ConnectionInfo(long queueAddress, int clientIndex, int status) {
            this.queueAddress = queueAddress;
            this.clientIndex = clientIndex;
            this.status = status;
        }
    }

    private static native ConnectionInfo clientConnect(String shmPrefix, String clientName);

    private static native void clientDisconnect();

}
