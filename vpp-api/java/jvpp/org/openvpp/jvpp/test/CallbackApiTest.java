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

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.GetNodeIndexCallback;
import org.openvpp.jvpp.callback.ShowVersionCallback;
import org.openvpp.jvpp.callback.SwInterfaceCallback;
import org.openvpp.jvpp.dto.GetNodeIndex;
import org.openvpp.jvpp.dto.GetNodeIndexReply;
import org.openvpp.jvpp.dto.ShowVersion;
import org.openvpp.jvpp.dto.ShowVersionReply;
import org.openvpp.jvpp.dto.SwInterfaceDetails;
import org.openvpp.jvpp.dto.SwInterfaceDump;

public class CallbackApiTest {

    private static class TestCallback implements GetNodeIndexCallback, ShowVersionCallback, SwInterfaceCallback {

        @Override
        public void onGetNodeIndexReply(final GetNodeIndexReply msg) {
            System.out.printf("Received GetNodeIndexReply: context=%d, retval=%d, nodeIndex=%d\n",
                    msg.context, msg.retval, msg.nodeIndex);
        }
        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("Received ShowVersionReply: context=%d, retval=%d, program=%s, version=%s, " +
                    "buildDate=%s, buildDirectory=%s\n",
                    msg.context, msg.retval, new String(msg.program), new String(msg.version),
                    new String(msg.buildDate), new String(msg.buildDirectory));
        }

        @Override
        public void onSwInterfaceDetails(final SwInterfaceDetails msg) {
            System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, " +
                    "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                    new String(msg.interfaceName), msg.l2AddressLength, msg.adminUpDown,
                    msg.linkUpDown, msg.linkSpeed, (int)msg.linkMtu);
        }
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API");
        JVpp jvpp = new JVppImpl( new VppJNIConnection("CallbackApiTest"));
        jvpp.connect( new TestCallback());
        System.out.println("Successfully connected to VPP");

        System.out.println("Sending ShowVersion request...");
        jvpp.send(new ShowVersion());

        System.out.println("Sending GetNodeIndex request...");
        GetNodeIndex getNodeIndexRequest = new GetNodeIndex();
        getNodeIndexRequest.nodeName = "node0".getBytes();
        jvpp.send(getNodeIndexRequest);

        System.out.println("Sending SwInterfaceDump request...");
        SwInterfaceDump swInterfaceDumpRequest = new SwInterfaceDump();
        swInterfaceDumpRequest.nameFilterValid = 0;
        swInterfaceDumpRequest.nameFilter = "".getBytes();
        jvpp.send(swInterfaceDumpRequest);

        Thread.sleep(5000);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }
}
