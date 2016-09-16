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

package org.openvpp.jvpp.core.test;

import javax.xml.bind.DatatypeConverter;
import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.dto.ClassifyAddDelSession;
import org.openvpp.jvpp.core.dto.ClassifyAddDelSessionReply;
import org.openvpp.jvpp.core.dto.ClassifyAddDelTable;
import org.openvpp.jvpp.core.dto.ClassifyAddDelTableReply;
import org.openvpp.jvpp.core.dto.ClassifySessionDetailsReplyDump;
import org.openvpp.jvpp.core.dto.ClassifySessionDump;
import org.openvpp.jvpp.core.dto.ClassifyTableByInterface;
import org.openvpp.jvpp.core.dto.ClassifyTableByInterfaceReply;
import org.openvpp.jvpp.core.dto.ClassifyTableIds;
import org.openvpp.jvpp.core.dto.ClassifyTableIdsReply;
import org.openvpp.jvpp.core.dto.ClassifyTableInfo;
import org.openvpp.jvpp.core.dto.ClassifyTableInfoReply;
import org.openvpp.jvpp.core.dto.InputAclSetInterface;
import org.openvpp.jvpp.core.dto.InputAclSetInterfaceReply;
import org.openvpp.jvpp.core.future.FutureJVppCoreFacade;

/**
 * <p>Tests L2 ACL creation and read.<br> Equivalent to the following vppctl commands:<br>
 *
 * <pre>{@code
 * vppctl classify table mask l2 src
 * vppctl classify session acl-hit-next deny opaque-index 0 table-index 0 match l2 src 01:02:03:04:05:06
 * vppctl set int input acl intfc local0 l2-table 0
 * vppctl sh class table verbose
 * }
 * </pre>
 */
public class L2AclTest {

    private static final int LOCAL0_IFACE_ID = 0;

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
                new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                        (byte) 0xff, (byte) 0xff, 0x00, 0x00, 0x00, 0x00};
        return request;
    }

    private static ClassifyTableInfo createClassifyTableInfoRequest(final int tableId) {
        ClassifyTableInfo request = new ClassifyTableInfo();
        request.tableId = tableId;
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
                new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                        (byte) 0x05, (byte) 0x06, 0x00, 0x00, 0x00, 0x00};
        return request;
    }

    private static ClassifySessionDump createClassifySessionDumpRequest(final int newTableIndex) {
        ClassifySessionDump request = new ClassifySessionDump();
        request.tableId = newTableIndex;
        return request;
    }

    private static InputAclSetInterface aclSetInterface() {
        InputAclSetInterface request = new InputAclSetInterface();
        request.isAdd = 1;
        request.swIfIndex = LOCAL0_IFACE_ID;
        request.ip4TableIndex = ~0; // skip
        request.ip6TableIndex = ~0; // skip
        request.l2TableIndex = 0;
        return request;
    }

    private static ClassifyTableByInterface createClassifyTableByInterfaceRequest() {
        ClassifyTableByInterface request = new ClassifyTableByInterface();
        request.swIfIndex = LOCAL0_IFACE_ID;
        return request;
    }

    private static void print(ClassifyAddDelTableReply reply) {
        System.out.printf("ClassifyAddDelTableReply: %s\n", reply);
    }

    private static void print(ClassifyTableIdsReply reply) {
        System.out.printf("ClassifyTableIdsReply: %s\n", reply);
    }

    private static void print(final ClassifyTableInfoReply reply) {
        System.out.println(reply);
        if (reply != null) {
            System.out.println("Mask hex: " + DatatypeConverter.printHexBinary(reply.mask));
        }
    }

    private static void print(ClassifyAddDelSessionReply reply) {
        System.out.printf("ClassifyAddDelSessionReply: context=%s\n", reply);
    }

    private static void print(final ClassifySessionDetailsReplyDump reply) {
        System.out.println(reply);
        reply.classifySessionDetails.forEach(detail -> {
            System.out.println(detail);
            System.out.println("Match hex: " + DatatypeConverter.printHexBinary(detail.match));
        });
    }

    private static void print(final InputAclSetInterfaceReply reply) {
        System.out.printf("InputAclSetInterfaceReply: context=%s\n", reply);
    }

    private static void print(final ClassifyTableByInterfaceReply reply) {
        System.out.printf("ClassifyAddDelTableReply: %s\n", reply);
    }

    private static void testL2Acl() throws Exception {
        System.out.println("Testing L2 ACLs using Java callback API");
        final JVppRegistry registry = new JVppRegistryImpl("L2AclTest");
        final JVpp jvpp = new JVppCoreImpl();
        final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, jvpp);

        System.out.println("Successfully connected to VPP");
        Thread.sleep(1000);

        final ClassifyAddDelTableReply classifyAddDelTableReply =
                jvppFacade.classifyAddDelTable(createClassifyTable()).toCompletableFuture().get();
        print(classifyAddDelTableReply);

        final ClassifyTableIdsReply classifyTableIdsReply =
                jvppFacade.classifyTableIds(new ClassifyTableIds()).toCompletableFuture().get();
        print(classifyTableIdsReply);

        final ClassifyTableInfoReply classifyTableInfoReply =
                jvppFacade.classifyTableInfo(createClassifyTableInfoRequest(classifyAddDelTableReply.newTableIndex))
                        .toCompletableFuture().get();
        print(classifyTableInfoReply);

        final ClassifyAddDelSessionReply classifyAddDelSessionReply =
                jvppFacade.classifyAddDelSession(createClassifySession(classifyAddDelTableReply.newTableIndex))
                        .toCompletableFuture().get();
        print(classifyAddDelSessionReply);

        final ClassifySessionDetailsReplyDump classifySessionDetailsReplyDump =
                jvppFacade.classifySessionDump(createClassifySessionDumpRequest(classifyAddDelTableReply.newTableIndex))
                        .toCompletableFuture().get();
        print(classifySessionDetailsReplyDump);

        final InputAclSetInterfaceReply inputAclSetInterfaceReply =
                jvppFacade.inputAclSetInterface(aclSetInterface()).toCompletableFuture().get();
        print(inputAclSetInterfaceReply);

        final ClassifyTableByInterfaceReply classifyTableByInterfaceReply =
                jvppFacade.classifyTableByInterface(createClassifyTableByInterfaceRequest()).toCompletableFuture().get();
        print(classifyTableByInterfaceReply);

        System.out.println("Disconnecting...");
        registry.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testL2Acl();
    }
}
