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
import io.fd.vpp.jvpp.core.dto.MplsRouteAddDelReply;
import io.fd.vpp.jvpp.core.dto.MplsRouteAddDel;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;


public class MplsAddEosLabelSwap {

    private static final int MPLS_LABEL_INVALID = 0xfffff + 1;

    private static MplsRouteAddDel addNonEosMplsLookupRoute() {
        /*
        create loopback interface
        create loopback interface
         set interface state loop1 up
         set int ip address loop1 10.10.12.1/24
         mpls table add 0
         set interface mpls loop1 enable
         mpls local-label add eos 104 via 10.10.24.4 loop1 out-labels 104
        */
// vpp2:
//        mpls local-label add eos 104 via 10.10.24.4 host-veth24 out-labels 104
// vpp4:
//        mpls local-label add eos 104 ip4-lookup-in-table 0

        MplsRouteAddDel request = new MplsRouteAddDel();
        request.mrLabel = 104;
        request.mrEos = 1;
        request.mrTableId = 0; // is it id of mpls table or ip table?
        request.mrClassifyTableIndex = -1; // default value used in make test
        // request.mrCreateTableIfNeeded // not set in test_mpls.py
        request.mrIsAdd = 1;
        // request.mrIsClassify; // default value used in make test
        // request.mrIsMulticast; // default value used in make test
        // request.mrIsMultipath; // we just use single path
        // request.mrIsResolveHost; // default value used in make test
        // request.mrIsResolveAttached; // default value used in make test
        // request.mrIsInterfaceRx = 0; // default value, looks like CLI sets it only if l2-input-on or rx-ip4 is used
        // request.mrIsRpfId; // default value used in test_mpls.py
        request.mrNextHopProto = 2; // to do what cli is doing
        request.mrNextHopWeight = 1; // default value used in make test
        // request.mrNextHopPreference; // not set in make test


        request.mrNextHop = new byte[]{10, 10, 24, 4};
        request.mrNextHopNOutLabels = 1;
        request.mrNextHopSwIfIndex = 2;
        // request.mrNextHopTableId = 0; // default value used in tests
        request.mrNextHopViaLabel = MPLS_LABEL_INVALID; // default value used by make test
        request.mrNextHopOutLabelStack = new int[]{104};
        
        
        System.out.println("addNonEosMplsLookupRoute request: " + request);
        return request;
    }

    private static void testMplsLabelPush() throws Exception {
        System.out.println("Testing L2 ACLs using Java callback API");
        try (final JVppRegistry registry = new JVppRegistryImpl("L2AclExample");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {

            System.out.println("Successfully connected to VPP");
            Thread.sleep(1000);

            final MplsRouteAddDelReply reply =
                    jvppFacade.mplsRouteAddDel(addNonEosMplsLookupRoute()).toCompletableFuture().get();
            System.out.println("Reply: " + reply);

            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testMplsLabelPush();
    }
}
