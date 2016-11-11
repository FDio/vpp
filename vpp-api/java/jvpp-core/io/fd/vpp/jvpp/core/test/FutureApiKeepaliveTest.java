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

package io.fd.vpp.jvpp.core.test;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.dto.IpAddressDetailsReplyDump;
import io.fd.vpp.jvpp.core.dto.IpAddressDump;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetails;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetailsReplyDump;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDump;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;
import java.util.Arrays;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class FutureApiKeepaliveTest {

    private static final Logger LOG = Logger.getLogger(FutureApiKeepaliveTest.class.getName());

    private static void testFutureApi() throws Exception {
        LOG.info("Testing Java future API");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {
            LOG.info("Successfully connected to VPP");

            while (true) {
                try {

                    final SwInterfaceDump request = new SwInterfaceDump();
                    final CompletionStage<SwInterfaceDetailsReplyDump> ifcDumpFuture =
                            jvppFacade.swInterfaceDump(request);
                    final SwInterfaceDetailsReplyDump
                            swIfcDumpReply = ifcDumpFuture.toCompletableFuture().get(5, TimeUnit.SECONDS);
                    System.out.println("Executed ifc Dump: "
                            + swIfcDumpReply.swInterfaceDetails.get(0).context
                            + " ifcs: " + swIfcDumpReply.swInterfaceDetails.stream()
                            .map(swInterfaceDetails -> swInterfaceDetails.swIfIndex).collect(
                                    Collectors.toList()));

                    for (final SwInterfaceDetails swInterfaceDetail : swIfcDumpReply.swInterfaceDetails) {
                        final IpAddressDump request1 = new IpAddressDump();
                        request1.isIpv6 = 0;
                        request1.swIfIndex = swInterfaceDetail.swIfIndex;

                        final CompletionStage<IpAddressDetailsReplyDump> ipDumpFuture =
                                jvppFacade.ipAddressDump(request1);
                        final IpAddressDetailsReplyDump ipDetailsReplyDump =
                                ipDumpFuture.toCompletableFuture().get(5, TimeUnit.SECONDS);
                        if(ipDetailsReplyDump.ipAddressDetails.size() > 0) {
                            System.out.println("Executed ip Dump: "
                                + ipDetailsReplyDump.ipAddressDetails.get(0).context
                                + " ifcs: " + ipDetailsReplyDump.ipAddressDetails.stream()
                                .map(detail -> "" + Arrays.toString(detail.ip)).collect(
                                        Collectors.toList()));
                        }
                    }


                    Thread.sleep(1000);
                } catch (Exception e) {
                    System.out.println("FAIL!!! " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
