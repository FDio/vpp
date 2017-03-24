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

package io.fd.vpp.jvpp.snat.test;


import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.snat.JVppSnatImpl;
import io.fd.vpp.jvpp.snat.dto.SnatAddressDetailsReplyDump;
import io.fd.vpp.jvpp.snat.dto.SnatAddressDump;
import io.fd.vpp.jvpp.snat.future.FutureJVppSnatFacade;

import java.util.concurrent.Future;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(io.fd.vpp.jvpp.snat.test.FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testCallbackApi(args);
    }

    private static void testCallbackApi(String[] args) throws Exception {
        System.out.println("Testing Java callback API for acl plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("macipAclAddTest", args[0]);
             final FutureJVppSnatFacade jvpp = new FutureJVppSnatFacade(registry, new JVppSnatImpl())) {
            LOG.info("Successfully connected to VPP");

            testAclDump(jvpp);

            System.out.println("Disconnecting...");
        }
    }

    private static void testAclDump(FutureJVppSnatFacade jvpp) throws Exception {
        LOG.info("Sending ShowVersion request...");
        final SnatAddressDump request = new SnatAddressDump();

        final Future<SnatAddressDetailsReplyDump> replyFuture = jvpp.snatAddressDump(request).toCompletableFuture();
        final SnatAddressDetailsReplyDump reply = replyFuture.get();

        if (reply == null || reply.snatAddressDetails == null) {
            throw new IllegalStateException("Received null response for empty dump: " + reply);
        } else {
            LOG.info(
                    String.format(
                            "Received bridge-domain dump reply with list of bridge-domains: %s",
                            reply.snatAddressDetails));
        }
    }
}
