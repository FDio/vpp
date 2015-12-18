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

import org.openvpp.vppjapi.vppVersion;
import org.openvpp.vppjapi.vppInterfaceDetails;
import org.openvpp.vppjapi.vppInterfaceCounters;
import org.openvpp.vppjapi.vppBridgeDomainDetails;
import org.openvpp.vppjapi.vppIPv4Address;
import org.openvpp.vppjapi.vppIPv6Address;
import org.openvpp.vppjapi.vppVxlanTunnelDetails;

public class vppConn {
    private static final String LIBNAME = "libvppjni.so.0.0.0";

    static {
        try {
            loadLibrary();
        } catch (IOException | RuntimeException e) {
            System.out.printf ("Can't find vpp jni library: %s\n", LIBNAME);
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

    public native int clientConnect(String clientName);
    public native void clientDisconnect();
    public native int getRetval(int context, int release);
    public native String getInterfaceList (String nameFilter);
    public native int swIfIndexFromName (String interfaceName);
    public native String interfaceNameFromSwIfIndex (int swIfIndex);
    public native void clearInterfaceTable ();
    public native vppInterfaceDetails[] swInterfaceDump (byte nameFilterValid, byte [] nameFilter);
    public native int bridgeDomainIdFromName(String bridgeDomain);
    public native int findOrAddBridgeDomainId(String bridgeDomain);
    public native vppVersion getVppVersion();
    public native vppInterfaceCounters getInterfaceCounters(int swIfIndex);
    public native int[] bridgeDomainDump(int bdId);
    public native vppBridgeDomainDetails getBridgeDomainDetails(int bdId);
    public native vppL2Fib[] l2FibTableDump(int bdId);
    public native int bridgeDomainIdFromInterfaceName(String interfaceName);
    public native vppIPv4Address[] ipv4AddressDump(String interfaceName);
    public native vppIPv6Address[] ipv6AddressDump(String interfaceName);
    public native vppVxlanTunnelDetails[] vxlanTunnelDump(int swIfIndex);
    public native int setInterfaceDescription (String ifName, String ifDesc);
    public native String getInterfaceDescription (String ifName);
}
