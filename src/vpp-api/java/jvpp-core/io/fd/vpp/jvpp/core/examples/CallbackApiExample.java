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

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.callback.GetNodeIndexCallback;
import io.fd.vpp.jvpp.core.callback.ShowVersionCallback;
import io.fd.vpp.jvpp.core.callback.SwInterfaceCallback;
import io.fd.vpp.jvpp.core.dto.GetNodeIndex;
import io.fd.vpp.jvpp.core.dto.GetNodeIndexReply;
import io.fd.vpp.jvpp.core.dto.ShowVersion;
import io.fd.vpp.jvpp.core.dto.ShowVersionReply;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetails;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDump;
import java.nio.charset.StandardCharsets;

public class CallbackApiExample {

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API with JVppRegistry");
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackApiExample");
             final JVpp jvpp = new JVppCoreImpl()) {
            registry.register(jvpp, new TestCallback());

            System.out.println("Sending ShowVersion request...");
            final int result = jvpp.send(new ShowVersion());
            System.out.printf("ShowVersion send result = %d%n", result);

            System.out.println("Sending GetNodeIndex request...");
            GetNodeIndex getNodeIndexRequest = new GetNodeIndex();
            getNodeIndexRequest.nodeName = "non-existing-node".getBytes(StandardCharsets.UTF_8);
            jvpp.send(getNodeIndexRequest);

            System.out.println("Sending SwInterfaceDump request...");
            SwInterfaceDump swInterfaceDumpRequest = new SwInterfaceDump();
            swInterfaceDumpRequest.nameFilterValid = 0;
            swInterfaceDumpRequest.nameFilter = "".getBytes(StandardCharsets.UTF_8);
            jvpp.send(swInterfaceDumpRequest);

            Thread.sleep(1000);
            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    static class TestCallback implements GetNodeIndexCallback, ShowVersionCallback, SwInterfaceCallback {

        @Override
        public void onGetNodeIndexReply(final GetNodeIndexReply msg) {
            System.out.printf("Received GetNodeIndexReply: %s%n", msg);
        }

        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("Received ShowVersionReply: context=%d, program=%s, version=%s, "
                    + "buildDate=%s, buildDirectory=%s%n",
                msg.context,
                new String(msg.program, StandardCharsets.UTF_8),
                new String(msg.version, StandardCharsets.UTF_8),
                new String(msg.buildDate, StandardCharsets.UTF_8),
                new String(msg.buildDirectory, StandardCharsets.UTF_8));
        }

        @Override
        public void onSwInterfaceDetails(final SwInterfaceDetails msg) {
            System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, "
                    + "linkUpDown=%d, linkSpeed=%d, linkMtu=%d%n",
                new String(msg.interfaceName, StandardCharsets.UTF_8), msg.l2AddressLength, msg.adminUpDown,
                msg.linkUpDown, msg.linkSpeed, (int) msg.linkMtu);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }
}
