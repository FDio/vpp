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

package io.fd.vpp.jvpp.core.examples;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.dto.IpAddDelRoute;
import io.fd.vpp.jvpp.core.dto.IpAddDelRouteReply;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;

/**
 * Pushes mpls label on packets going to 10.10.24.0/24
 *
 * vpp1:
 * route add 10.10.24.0/24 via 10.10.12.2 loop0 out-labels 102 104
 *
 */
public class IpAddDelRouteExample {

    private static final int MPLS_LABEL_INVALID = 0xfffff + 1;
    private static final int LOCAL0_IFACE_ID = 0;

    private static IpAddDelRoute addRoute() {
        /*
        create loopback interface
         set interface loop0 up
         set int ip address loop0 10.10.12.1/24
         mpls table add 0
         set interface mpls loop0 enable
        */
        IpAddDelRoute request = new IpAddDelRoute();
        request.nextHopSwIfIndex = 1; // interface created before
        // request.tableId = 0; // use default fable
        // request.classifyTableIndex; no need to set, because isClassify is not set
        // request.nextHopTableId = 0; // use default table for next hop
        // request.createVrfIfNeeded; not set in tests
        request.isAdd = 1;
        // request.isDrop; // not set in test_mpls.py
        // request.isUnreach; // not set in test_mpls.py
        // request.isProhibit; // not set in test_mpls.py
        request.isIpv6 = 0;
        // request.isLocal; // not set in test_mpls.py
        // request.isClassify; // not set in test_mpls.py
        // request.isMultipath; // we just use single path
        // request.isResolveHost; // test_mpls.py uses 0 as default
        // request.isResolveAttached; // test_mpls.py uses 0 as default
        // request.isL2Bridged = 1; // test_mpls.py always sets it to 1 (resulting in frp_proto = DPO_PROTO_ETHERNET)
        // but CLI does not
        // request.notLast; not used
        request.nextHopWeight = 1; // default value used in make test
        // request.nextHopPreference; // not set in test_mpls.py
        request.dstAddressLength = (byte) 24;
        request.dstAddress = new byte[]{(byte) 10, (byte) 10, (byte) 24, (byte) 0};
        request.nextHopAddress = new byte[]{(byte) 10, (byte) 10, (byte) 12, (byte) 2};
        request.nextHopNOutLabels = 2;
        request.nextHopViaLabel = MPLS_LABEL_INVALID;
        request.nextHopOutLabelStack = new int[]{102, 104};
        System.out.println("add ip route with labels request: " + request);
        return request;
    }

    private static void testMplsLabelPush() throws Exception {
        System.out.println("Testing L2 ACLs using Java callback API");
        try (final JVppRegistry registry = new JVppRegistryImpl("L2AclExample");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {

            System.out.println("Successfully connected to VPP");
            Thread.sleep(1000);

            final IpAddDelRouteReply reply =
                    jvppFacade.ipAddDelRoute(addRoute()).toCompletableFuture().get();
            System.out.println("Reply: " + reply);

            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testMplsLabelPush();
    }
}
