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

package org.openvpp.jvpp.test;

import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.dto.ClassifyAddDelSession;
import org.openvpp.jvpp.dto.ClassifyAddDelSessionReply;
import org.openvpp.jvpp.dto.ClassifyAddDelTable;
import org.openvpp.jvpp.dto.ClassifyAddDelTableReply;
import org.openvpp.jvpp.dto.InputAclSetInterface;
import org.openvpp.jvpp.dto.InputAclSetInterfaceReply;
import org.openvpp.jvpp.future.FutureJVppFacade;

/**
 * <p>Tests L2 ACL creation.<br>
 * Equivalent to the following vppctl commands:<br>
 *
 * <pre>{@code
 * vppctl classify table mask l2 src
 * vppctl classify session acl-hit-next deny opaque-index 0 table-index 0 match l2 src 01:02:03:04:05:06
 * vppctl vppctl set int input acl intfc local0 l2-table 0
 * }
 * </pre>
 *
 * To verify invoke:<br>
 * {@code vppctl sh class table verbose}
 */
public class L2AclTest {

    private static ClassifyAddDelTable createClassifyTable() {
        ClassifyAddDelTable request = new ClassifyAddDelTable();
        request.isAdd = 1;
        request.tableIndex = ~0; // default
        request.nbuckets = 2;
        request.memorySize = 2 << 20;
        request.nextTableIndex = ~0; // default
        request.missNextIndex = ~0; // default
        request.skipNVectors = 0;
        request.matchNVectors = 1;
        request.mask =
                new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                        (byte) 0xff, (byte) 0xff, 0x00, 0x00, 0x00, 0x00};
        return request;
    }

    private static ClassifyAddDelSession createClassifySession(final int tableIndex) {
        ClassifyAddDelSession request = new ClassifyAddDelSession();
        request.isAdd = 1;
        request.tableIndex = tableIndex;
        request.hitNextIndex = 0; // deny
        request.opaqueIndex = 0;
        request.advance = 0; // default
        // match 01:02:03:04:05:06 mac address
        request.match =
                new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                        (byte) 0x05, (byte) 0x06, 0x00, 0x00, 0x00, 0x00};
        return request;
    }

    private static InputAclSetInterface aclSetInterface() {
        InputAclSetInterface request = new InputAclSetInterface();
        request.isAdd = 1;
        request.swIfIndex = 0;
        request.ip4TableIndex = ~0; // skip
        request.ip6TableIndex = ~0; // skip
        request.l2TableIndex = 0;
        return request;
    }

    private static void print(ClassifyAddDelTableReply reply) {
        System.out.printf("ClassifyAddDelTableReply: context=%d, " +
                        "newTableIndex=%d, skipNVectors=%d, matchNVectors=%d\n",
                reply.context,
                reply.newTableIndex,
                reply.skipNVectors,
                reply.matchNVectors);
    }

    private static void print(ClassifyAddDelSessionReply reply) {
        System.out.printf("ClassifyAddDelSessionReply: context=%d\n",
                reply.context);
    }

    private static void print(final InputAclSetInterfaceReply reply) {
        System.out.printf("InputAclSetInterfaceReply: context=%d\n",
                reply.context);

    }

    private static void testL2Acl() throws Exception {
        System.out.println("Testing L2 ACLs using Java callback API");
        final JVppImpl jvpp = new JVppImpl(new VppJNIConnection("L2AclTest"));
        final FutureJVppFacade jvppFacade = new FutureJVppFacade(jvpp);

        System.out.println("Successfully connected to VPP");
        Thread.sleep(1000);

        final ClassifyAddDelTableReply classifyAddDelTableReply =
                jvppFacade.classifyAddDelTable(createClassifyTable()).toCompletableFuture().get();
        print(classifyAddDelTableReply);

        final ClassifyAddDelSessionReply classifyAddDelSessionReply =
                jvppFacade.classifyAddDelSession(createClassifySession(classifyAddDelTableReply.newTableIndex))
                        .toCompletableFuture().get();
        print(classifyAddDelSessionReply);

        final InputAclSetInterfaceReply inputAclSetInterfaceReply =
                jvppFacade.inputAclSetInterface(aclSetInterface()).toCompletableFuture().get();
        print(inputAclSetInterfaceReply);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testL2Acl();
    }
}
