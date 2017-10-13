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


public class MplsRouteAddDelExample {

    private static final int MPLS_LABEL_INVALID = 0xfffff + 1;

    private static MplsRouteAddDel addNonEosMplsLookupRoute() {
        /*
        create loopback interface
         set interface loop0 up
         set int ip address loop0 10.10.12.1/24
         mpls table add 0
         set interface mpls loop0 enable
        */
// vpp2:
//        mpls local-label add non-eos 102 mpls-lookup-in-table 0
//        mpls local-label add eos 104 via 10.10.24.4 host-veth24 out-labels 104
// vpp4:
//        mpls local-label add eos 104 ip4-lookup-in-table 0

        /*

                #
        # A simple MPLS xconnect - eos label in label out
        #
        route_32_eos = VppMplsRoute(self, 32, 1,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[33])])

        route_34_neos = VppMplsRoute(self, 34, 0,
                                     [VppRoutePath("0.0.0.0",
                                                   0xffffffff,
                                                   nh_via_label=32,
                                                   labels=[44, 46])])

                                                   #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_table_id=0)])

                                                          #
        # A simple MPLS xconnect - non-eos label in label out
        #
        route_32_neos = VppMplsRoute(self, 32, 0,
                                     [VppRoutePath(self.pg0.remote_ip4,
                                                   self.pg0.sw_if_index,
                                                   labels=[33])])


        # Create a label entry to for 55 that does L2 input to the tunnel
        #
        route_55_eos = VppMplsRoute(
            self, 55, 1,
            [VppRoutePath("0.0.0.0",
                          mpls_tun_1.sw_if_index,
                          is_interface_rx=1,
                          proto=DpoProto.DPO_PROTO_ETHERNET)])


      else if (unformat (line_input,
			 "mpls-lookup-in-table %d",
			 &rpath.frp_fib_index))
      {
          rpath.frp_proto = DPO_PROTO_MPLS;
          rpath.frp_sw_if_index = FIB_NODE_INDEX_INVALID; (-1)
	  pfx.fp_payload_proto = DPO_PROTO_MPLS;

}

self._test.vapi.mpls_route_add_del(
                self.local_label,
                self.eos_bit,
                path.proto,
                path.nh_addr,
                path.nh_itf,
                is_multicast=self.is_multicast,
                is_multipath=is_multipath,
                table_id=self.table_id,
                is_interface_rx=path.is_interface_rx,
                is_rpf_id=path.is_rpf_id,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(
                    path.nh_labels),
                next_hop_via_label=path.nh_via_label,
                next_hop_table_id=path.nh_table_id)


         */

        MplsRouteAddDel request = new MplsRouteAddDel();
        request.mrLabel = 102;
        request.mrEos = 0;
        request.mrTableId = 0; // is it id of mpls table or ip table?
        request.mrClassifyTableIndex = -1; // default value used in make test
        // request.mrCreateTableIfNeeded // not set in test_mpls.py
        request.mrIsAdd = 1;
        // request.mrIsClassify; // default value used in make test
        // request.mrIsMulticast; // default value used in make test
        // request.mrIsMultipath; // we just use single path
        // request.mrIsResolveHost; // default value used in make test
        // request.mrIsResolveAttached; // default value used in make test
        request.mrIsInterfaceRx = 0; // default value, looks like CLI sets it only if l2-input-on or rx-ip4 is used
        // request.mrIsRpfId; // default value used in test_mpls.py
        request.mrNextHopProto = 2; // to do what cli is doing
        request.mrNextHopWeight = 1; // default value used in make test
        // request.mrNextHopPreference; // not set in make test


        request.mrNextHop = new byte[4]; // we just POP, so setting 0.0.0.0
        request.mrNextHopNOutLabels = 0; // no labels, its just POP
        request.mrNextHopSwIfIndex = -1; // this is what cli is doing
        // request.mrNextHopTableId = 0; // default value used in tests
        request.mrNextHopViaLabel = MPLS_LABEL_INVALID; // default value used by make test
        request.mrNextHopOutLabelStack = new int[0];
        
        
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
