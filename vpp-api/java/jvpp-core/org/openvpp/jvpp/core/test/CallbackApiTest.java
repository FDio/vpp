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

package org.openvpp.jvpp.core.test;

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.callback.GetNodeIndexCallback;
import org.openvpp.jvpp.core.callback.ShowVersionCallback;
import org.openvpp.jvpp.core.callback.SwInterfaceCallback;
import org.openvpp.jvpp.core.dto.GetNodeIndex;
import org.openvpp.jvpp.core.dto.GetNodeIndexReply;
import org.openvpp.jvpp.core.dto.ShowVersion;
import org.openvpp.jvpp.core.dto.ShowVersionReply;
import org.openvpp.jvpp.core.dto.SwInterfaceDetails;
import org.openvpp.jvpp.core.dto.SwInterfaceDump;

public class CallbackApiTest {

    static class TestCallback implements GetNodeIndexCallback, ShowVersionCallback, SwInterfaceCallback {

        @Override
        public void onGetNodeIndexReply(final GetNodeIndexReply msg) {
            System.out.printf("Received GetNodeIndexReply: context=%d, nodeIndex=%d\n",
                msg.context, msg.nodeIndex);
        }

        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("Received ShowVersionReply: context=%d, program=%s, version=%s, "
                    + "buildDate=%s, buildDirectory=%s\n",
                msg.context, new String(msg.program), new String(msg.version),
                new String(msg.buildDate), new String(msg.buildDirectory));
        }

        @Override
        public void onSwInterfaceDetails(final SwInterfaceDetails msg) {
            System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, "
                    + "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                new String(msg.interfaceName), msg.l2AddressLength, msg.adminUpDown,
                msg.linkUpDown, msg.linkSpeed, (int) msg.linkMtu);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d\n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API with JVppRegistry");
        JVppRegistry registry = new JVppRegistryImpl("CallbackApiTest");
        JVpp jvpp = new JVppCoreImpl();

        registry.register(jvpp, new TestCallback());

        System.out.println("Sending ShowVersion request...");
        final int result = jvpp.send(new ShowVersion());
        System.out.printf("ShowVersion send result = %d\n", result);

        System.out.println("Sending GetNodeIndex request...");
        GetNodeIndex getNodeIndexRequest = new GetNodeIndex();
        getNodeIndexRequest.nodeName = "non-existing-node".getBytes();
        jvpp.send(getNodeIndexRequest);

        System.out.println("Sending SwInterfaceDump request...");
        SwInterfaceDump swInterfaceDumpRequest = new SwInterfaceDump();
        swInterfaceDumpRequest.nameFilterValid = 0;
        swInterfaceDumpRequest.nameFilter = "".getBytes();
        jvpp.send(swInterfaceDumpRequest);

        Thread.sleep(1000);

        System.out.println("Disconnecting...");
        registry.close();
        Thread.sleep(1000);
    }
}
