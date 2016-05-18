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
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.GetNodeIndexCallback;
import org.openvpp.jvpp.callback.ShowVersionCallback;
import org.openvpp.jvpp.dto.*;

public class OnErrorCallbackTest {

    private static class TestCallback implements GetNodeIndexCallback, ShowVersionCallback{

        @Override
        public void onGetNodeIndexReply(final GetNodeIndexReply msg) {
            System.out.printf("Received GetNodeIndexReply: context=%d, nodeIndex=%d\n",
                    msg.context, msg.nodeIndex);
        }
        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("Received ShowVersionReply: context=%d, program=%s, version=%s, " +
                    "buildDate=%s, buildDirectory=%s\n",
                    msg.context, new String(msg.program), new String(msg.version),
                    new String(msg.buildDate), new String(msg.buildDirectory));
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d\n", ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
        }
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API");
        JVpp jvpp = new JVppImpl(new VppJNIConnection("CallbackApiTest"));
        jvpp.connect(new TestCallback());
        System.out.println("Successfully connected to VPP");

        System.out.println("Sending ShowVersion request...");
        jvpp.send(new ShowVersion());

        System.out.println("Sending GetNodeIndex request...");
        GetNodeIndex getNodeIndexRequest = new GetNodeIndex();
        getNodeIndexRequest.nodeName = "dummyNode".getBytes();
        jvpp.send(getNodeIndexRequest);

        Thread.sleep(5000);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }
}
