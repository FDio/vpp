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

public class FutureApiExample {

    private static final Logger LOG = Logger.getLogger(FutureApiExample.class.getName());

    private static void testShowVersion(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending ShowVersion request...");
        final Future<ShowVersionReply> replyFuture = jvpp.showVersion(new ShowVersion()).toCompletableFuture();
        final ShowVersionReply reply = replyFuture.get();
        LOG.info(
            String.format(
                "Received ShowVersionReply: context=%d, program=%s, version=%s, buildDate=%s, buildDirectory=%s%n",
                reply.context, new String(reply.program, StandardCharsets.UTF_8),
                new String(reply.version, StandardCharsets.UTF_8),
                new String(reply.buildDate, StandardCharsets.UTF_8),
                new String(reply.buildDirectory, StandardCharsets.UTF_8)));
    }

    private static void testEmptyBridgeDomainDump(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending ShowVersion request...");
        final BridgeDomainDump request = new BridgeDomainDump();
        request.bdId = -1; // dump call

        final CompletableFuture<BridgeDomainDetailsReplyDump>
            replyFuture = jvpp.bridgeDomainDump(request).toCompletableFuture();
        final BridgeDomainDetailsReplyDump reply = replyFuture.get();

        if (reply == null || reply.bridgeDomainDetails == null) {
            LOG.severe("Received null response for empty dump: " + reply);
        } else {
            LOG.info(
                String.format(
                    "Received bridge-domain dump reply with list of bridge-domains: %s",
                    reply.bridgeDomainDetails));
        }
    }

    private static void testGetNodeIndex(final FutureJVppCoreFacade jvpp) {
        LOG.info("Sending GetNodeIndex request...");
        final GetNodeIndex request = new GetNodeIndex();
        request.nodeName = "non-existing-node".getBytes(StandardCharsets.UTF_8);
        final Future<GetNodeIndexReply> replyFuture = jvpp.getNodeIndex(request).toCompletableFuture();
        try {
            final GetNodeIndexReply reply = replyFuture.get();
            LOG.info(
                String.format(
                    "Received GetNodeIndexReply: context=%d, nodeIndex=%d%n", reply.context, reply.nodeIndex));
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "GetNodeIndex request failed", e);
        }
    }

    private static void testSwInterfaceDump(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending SwInterfaceDump request...");
        final SwInterfaceDump request = new SwInterfaceDump();
        request.nameFilterValid = 0;
        request.nameFilter = "".getBytes(StandardCharsets.UTF_8);

        final Future<SwInterfaceDetailsReplyDump> replyFuture = jvpp.swInterfaceDump(request).toCompletableFuture();
        final SwInterfaceDetailsReplyDump reply = replyFuture.get();
        for (SwInterfaceDetails details : reply.swInterfaceDetails) {
            Objects.requireNonNull(details, "reply.swInterfaceDetails contains null element!");
            LOG.info(
                String.format("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, "
                        + "linkUpDown=%d, linkSpeed=%d, linkMtu=%d%n",
                    new String(details.interfaceName, StandardCharsets.UTF_8),
                    details.l2AddressLength, details.adminUpDown,
                    details.linkUpDown, details.linkSpeed, (int) details.linkMtu));
        }
    }

    private static void testFutureApi() throws Exception {
        LOG.info("Testing Java future API");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiExample");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {
            LOG.info("Successfully connected to VPP");

            testEmptyBridgeDomainDump(jvppFacade);
            testShowVersion(jvppFacade);
            testGetNodeIndex(jvppFacade);
            testSwInterfaceDump(jvppFacade);

            LOG.info("Disconnecting...");
        }
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
