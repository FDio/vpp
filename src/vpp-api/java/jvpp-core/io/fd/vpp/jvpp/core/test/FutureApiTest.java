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
import io.fd.vpp.jvpp.core.dto.BridgeDomainDetailsReplyDump;
import io.fd.vpp.jvpp.core.dto.BridgeDomainDump;
import io.fd.vpp.jvpp.core.dto.GetNodeIndex;
import io.fd.vpp.jvpp.core.dto.GetNodeIndexReply;
import io.fd.vpp.jvpp.core.dto.ShowVersion;
import io.fd.vpp.jvpp.core.dto.ShowVersionReply;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetails;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetailsReplyDump;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDump;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testFutureApi(args);
    }

    private static void testFutureApi(String[] args) throws Exception {
        LOG.info("Testing Java future API for core plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {
            LOG.info("Successfully connected to VPP");

            testEmptyBridgeDomainDump(jvppFacade);

            LOG.info("Disconnecting...");
        }
    }

    private static void testEmptyBridgeDomainDump(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending BridgeDomainDump request...");
        final BridgeDomainDump request = new BridgeDomainDump();
        request.bdId = -1; // dump call

        final CompletableFuture<BridgeDomainDetailsReplyDump>
            replyFuture = jvpp.bridgeDomainDump(request).toCompletableFuture();
        final BridgeDomainDetailsReplyDump reply = replyFuture.get();

        if (reply == null || reply.bridgeDomainDetails == null) {
            throw new IllegalStateException("Received null response for empty dump: " + reply);
        } else {
            LOG.info(
                String.format(
                    "Received bridge-domain dump reply with list of bridge-domains: %s",
                    reply.bridgeDomainDetails));
        }
    }


}
