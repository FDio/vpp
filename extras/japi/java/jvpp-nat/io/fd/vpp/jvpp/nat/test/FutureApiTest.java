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

package io.fd.vpp.jvpp.nat.test;


import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.nat.JVppNatImpl;
import io.fd.vpp.jvpp.nat.dto.Nat44AddressDetailsReplyDump;
import io.fd.vpp.jvpp.nat.dto.Nat44AddressDump;
import io.fd.vpp.jvpp.nat.future.FutureJVppNatFacade;

import java.util.concurrent.Future;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(io.fd.vpp.jvpp.nat.test.FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testCallbackApi(args);
    }

    private static void testCallbackApi(String[] args) throws Exception {
        LOG.info("Testing Java callback API for nat plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppNatFacade jvpp = new FutureJVppNatFacade(registry, new JVppNatImpl())) {
            LOG.info("Successfully connected to VPP");

            testAclDump(jvpp);

            LOG.info("Disconnecting...");
        }
    }

    private static void testAclDump(FutureJVppNatFacade jvpp) throws Exception {
        LOG.info("Sending Nat44AddressDump request...");
        final Nat44AddressDump request = new Nat44AddressDump();

        final Future<Nat44AddressDetailsReplyDump> replyFuture = jvpp.nat44AddressDump(request).toCompletableFuture();
        final Nat44AddressDetailsReplyDump reply = replyFuture.get();

        if (reply == null || reply.nat44AddressDetails == null) {
            throw new IllegalStateException("Received null response for empty dump: " + reply);
        } else {
            LOG.info(
                    String.format(
                            "Received nat address dump reply with list of nat address: %s",
                            reply.nat44AddressDetails));
        }
    }
}
