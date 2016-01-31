/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

package org.openvpp.vppjapi;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.openvpp.vppjapi.vppVersion;
import org.openvpp.vppjapi.vppInterfaceDetails;
import org.openvpp.vppjapi.vppInterfaceCounters;
import org.openvpp.vppjapi.vppBridgeDomainDetails;
import org.openvpp.vppjapi.vppIPv4Address;
import org.openvpp.vppjapi.vppIPv6Address;
import org.openvpp.vppjapi.vppVxlanTunnelDetails;

public class vppConn implements AutoCloseable {
    private static final String LIBNAME = "libvppjni.so.0.0.0";

    static {
        try {
            loadLibrary();
        } catch (IOException | RuntimeException e) {
            System.out.printf ("Can't find vpp jni library: %s\n", LIBNAME);
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
      try (final InputStream is = vppConn.class.getResourceAsStream('/' + LIBNAME)) {
          if (is == null) {
            throw new IOException(String.format("Failed to open library resource %s",
                                                LIBNAME));
          }
          loadStream(is);
        }
    }

    private static vppConn currentConnection = null;
    private final AtomicBoolean disconnected = new AtomicBoolean(false);
    private final String clientName;

    // Hidden on purpose to prevent external instantiation
    vppConn(final String clientName) throws IOException {
        this.clientName = clientName;

        synchronized (vppConn.class) {
            if (currentConnection != null) {
                throw new IOException("Already connected as " + currentConnection.clientName);
            }

            final int ret = clientConnect(clientName);
            if (ret != 0) {
                throw new IOException("Connection returned error " + ret);
            }

            currentConnection = this;
        }
    }

    @Override
    public final void close() {
        if (disconnected.compareAndSet(false, true)) {
            synchronized (vppConn.class) {
                clientDisconnect();
                currentConnection = null;
            }
        }
    }

    /**
     * Check if this instance is connected.
     *
     * @throws IllegalStateException if this instance was disconnected.
     */
    protected final void checkConnected() {
        if (disconnected.get()) {
            throw new IllegalStateException("Disconnected client " + clientName);
        }
    }

    public final int getRetval(int context, int release) {
        checkConnected();
        return getRetval0(context, release);
    }

    public final String getInterfaceList (String nameFilter) {
        checkConnected();
        return getInterfaceList0(nameFilter);
    }

    public final int swIfIndexFromName (String interfaceName) {
        checkConnected();
        return swIfIndexFromName0(interfaceName);
    }

    public final String interfaceNameFromSwIfIndex (int swIfIndex) {
        checkConnected();
        return interfaceNameFromSwIfIndex0(swIfIndex);
    }

    public final void clearInterfaceTable () {
        checkConnected();
        clearInterfaceTable0();
    }

    public final vppInterfaceDetails[] swInterfaceDump (byte nameFilterValid, byte [] nameFilter) {
        checkConnected();
        return swInterfaceDump0(nameFilterValid, nameFilter);
    }

    public final int bridgeDomainIdFromName(String bridgeDomain) {
        checkConnected();
        return bridgeDomainIdFromName0(bridgeDomain);
    }

    public final int findOrAddBridgeDomainId(String bridgeDomain) {
        checkConnected();
        return findOrAddBridgeDomainId0(bridgeDomain);
    }

    public final vppVersion getVppVersion() {
        checkConnected();
        return getVppVersion0();
    }

    public final vppInterfaceCounters getInterfaceCounters(int swIfIndex) {
        checkConnected();
        return getInterfaceCounters0(swIfIndex);
    }

    public final int[] bridgeDomainDump(int bdId) {
        checkConnected();
        return bridgeDomainDump0(bdId);
    }

    public final vppBridgeDomainDetails getBridgeDomainDetails(int bdId) {
        checkConnected();
        return getBridgeDomainDetails0(bdId);
    }

    public final vppL2Fib[] l2FibTableDump(int bdId) {
        checkConnected();
        return l2FibTableDump0(bdId);
    }

    public final int bridgeDomainIdFromInterfaceName(String interfaceName) {
        checkConnected();
        return bridgeDomainIdFromInterfaceName0(interfaceName);
    }

    public final vppIPv4Address[] ipv4AddressDump(String interfaceName) {
        checkConnected();
        return ipv4AddressDump0(interfaceName);
    }

    public final vppIPv6Address[] ipv6AddressDump(String interfaceName) {
        checkConnected();
        return ipv6AddressDump0(interfaceName);
    }

    public final vppVxlanTunnelDetails[] vxlanTunnelDump(int swIfIndex) {
        checkConnected();
        return vxlanTunnelDump0(swIfIndex);
    }

    public final int setInterfaceDescription(String ifName, String ifDesc) {
        checkConnected();
        return setInterfaceDescription0(ifName, ifDesc);
    }

    public final String getInterfaceDescription(String ifName) {
        checkConnected();
        return getInterfaceDescription0(ifName);
    }

    private static native int clientConnect(String clientName);
    private static native void clientDisconnect();
    private static native int getRetval0(int context, int release);
    private static native String getInterfaceList0(String nameFilter);
    private static native int swIfIndexFromName0(String interfaceName);
    private static native String interfaceNameFromSwIfIndex0(int swIfIndex);
    private static native void clearInterfaceTable0();
    private static native vppInterfaceDetails[] swInterfaceDump0(byte nameFilterValid, byte [] nameFilter);
    private static native int bridgeDomainIdFromName0(String bridgeDomain);
    private static native int findOrAddBridgeDomainId0(String bridgeDomain);
    private static native vppVersion getVppVersion0();
    private static native vppInterfaceCounters getInterfaceCounters0(int swIfIndex);
    private static native int[] bridgeDomainDump0(int bdId);
    private static native vppBridgeDomainDetails getBridgeDomainDetails0(int bdId);
    private static native vppL2Fib[] l2FibTableDump0(int bdId);
    private static native int bridgeDomainIdFromInterfaceName0(String interfaceName);
    private static native vppIPv4Address[] ipv4AddressDump0(String interfaceName);
    private static native vppIPv6Address[] ipv6AddressDump0(String interfaceName);
    private static native vppVxlanTunnelDetails[] vxlanTunnelDump0(int swIfIndex);
    private static native int setInterfaceDescription0(String ifName, String ifDesc);
    private static native String getInterfaceDescription0(String ifName);
}
