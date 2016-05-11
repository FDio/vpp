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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.dto.GetNodeIndex;
import org.openvpp.jvpp.dto.GetNodeIndexReply;
import org.openvpp.jvpp.dto.JVppReply;
import org.openvpp.jvpp.dto.ShowVersion;
import org.openvpp.jvpp.dto.ShowVersionReply;
import org.openvpp.jvpp.dto.SwInterfaceDetails;
import org.openvpp.jvpp.dto.SwInterfaceDetailsReplyDump;
import org.openvpp.jvpp.dto.SwInterfaceDump;
import org.openvpp.jvpp.future.FutureJVppFacade;
import org.openvpp.jvpp.future.FutureJVppFacadeCallback;

public class FutureApiTest {

    private static void testShowVersion(final FutureJVppFacade jvpp) {
        System.out.println("Sending ShowVersion request...");
        try {
            Objects.requireNonNull(jvpp,"jvpp is null");
            final Future<ShowVersionReply> replyFuture = jvpp.showVersion(new ShowVersion()).toCompletableFuture();
            Objects.requireNonNull(replyFuture,"replyFuture is null");
            final ShowVersionReply reply = replyFuture.get();
            Objects.requireNonNull(reply,"reply is null");
            System.out.printf("Received ShowVersionReply: context=%d, retval=%d, program=%s, " +
                            "version=%s, buildDate=%s, buildDirectory=%s\n",
                    reply.context, reply.retval, new String(reply.program), new String(reply.version),
                    new String(reply.buildDate), new String(reply.buildDirectory));
        } catch (Exception e) {
            System.err.printf("ShowVersion request failed:\n");
            e.printStackTrace();
        }
    }

    /**
     * This test will fail with some error code if node 'node0' is not defined.
     * TODO: consider adding error messages specific for given api calls
     */
    private static void testGetNodeIndex(final FutureJVppFacade jvpp) {
        System.out.println("Sending GetNodeIndex request...");
        try {
            Objects.requireNonNull(jvpp,"jvpp is null");
            final GetNodeIndex request = new GetNodeIndex();
            request.nodeName = "node0".getBytes();
            final Future<GetNodeIndexReply> replyFuture = jvpp.getNodeIndex(request).toCompletableFuture();
            Objects.requireNonNull(replyFuture,"replyFuture is null");
            final GetNodeIndexReply reply = replyFuture.get();
            Objects.requireNonNull(reply,"reply is null");
            System.out.printf("Received GetNodeIndexReply: context=%d, retval=%d, nodeIndex=%d\n",
                    reply.context, reply.retval, reply.nodeIndex);
        } catch (Exception e) {
            System.err.printf("GetNodeIndex request failed:\n");
            e.printStackTrace();
        }
    }

    private static void testSwInterfaceDump(final FutureJVppFacade jvpp) {
        System.out.println("Sending SwInterfaceDump request...");
        try {
            Objects.requireNonNull(jvpp,"SwInterfaceDetailsReplyDump is null!");
            final SwInterfaceDump request = new SwInterfaceDump();
            request.nameFilterValid = 0;
            request.nameFilter = "".getBytes();
            final Future<SwInterfaceDetailsReplyDump> replyFuture = jvpp.swInterfaceDump(request).toCompletableFuture();
            Objects.requireNonNull(replyFuture,"replyFuture is null");
            final SwInterfaceDetailsReplyDump reply = replyFuture.get();
            Objects.requireNonNull(reply.swInterfaceDetails, "SwInterfaceDetailsReplyDump.swInterfaceDetails is null!");
            for (SwInterfaceDetails details : reply.swInterfaceDetails) {
                Objects.requireNonNull(details, "reply.swInterfaceDetails contains null element!");
                System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, " +
                                "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                        new String(details.interfaceName), details.l2AddressLength, details.adminUpDown,
                        details.linkUpDown, details.linkSpeed, (int) details.linkMtu);
            }
        } catch(NullPointerException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (Exception e) {
            System.err.printf("SwInterfaceDump request failed:\n");
            e.printStackTrace();
        }
    }

    private static void testFutureApi() throws Exception {
        System.out.println("Testing Java future API");

        final Map<Integer, CompletableFuture<? extends JVppReply<?>>>  map = new HashMap<>();
        final org.openvpp.jvpp.JVppImpl impl =
                new org.openvpp.jvpp.JVppImpl(VppJNIConnection.create("FutureApiTest", new FutureJVppFacadeCallback(map)));
        final FutureJVppFacade jvppFacade = new FutureJVppFacade(impl, map);
        System.out.println("Successfully connected to VPP");

        testShowVersion(jvppFacade);
        testGetNodeIndex(jvppFacade);
        testSwInterfaceDump(jvppFacade);

        System.out.println("Disconnecting...");
        // TODO we should consider adding jvpp.close(); to the facade
        impl.close();
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
