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

import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.core.JVppCore;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.callback.GetNodeIndexCallback;
import org.openvpp.jvpp.core.callback.ShowVersionCallback;
import org.openvpp.jvpp.core.callfacade.CallbackJVppCoreFacade;
import org.openvpp.jvpp.core.dto.GetNodeIndex;
import org.openvpp.jvpp.core.dto.GetNodeIndexReply;
import org.openvpp.jvpp.core.dto.ShowVersionReply;

/**
 * CallbackJVppFacade together with CallbackJVppFacadeCallback allow for setting different callback for each request.
 * This is more convenient than the approach shown in CallbackApiTest.
 */
public class CallbackJVppFacadeTest {

    private static ShowVersionCallback showVersionCallback1 = new ShowVersionCallback() {
        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("ShowVersionCallback1 received ShowVersionReply: context=%d, program=%s,"
                    + "version=%s, buildDate=%s, buildDirectory=%s\n", msg.context, new String(msg.program),
                new String(msg.version), new String(msg.buildDate), new String(msg.buildDirectory));
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception in showVersionCallback1: call=%s, reply=%d, context=%d\n",
                ex.getMethodName(), ex.getErrorCode(), ex.getCtxId());
        }
    };

    private static ShowVersionCallback showVersionCallback2 = new ShowVersionCallback() {
        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            System.out.printf("ShowVersionCallback2 received ShowVersionReply: context=%d, program=%s,"
                    + "version=%s, buildDate=%s, buildDirectory=%s\n", msg.context, new String(msg.program),
                new String(msg.version), new String(msg.buildDate), new String(msg.buildDirectory));
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception in showVersionCallback2: call=%s, reply=%d, context=%d\n",
                ex.getMethodName(), ex.getErrorCode(), ex.getCtxId());
        }

    };

    private static GetNodeIndexCallback getNodeIndexCallback = new GetNodeIndexCallback() {
        @Override
        public void onGetNodeIndexReply(final GetNodeIndexReply msg) {
            System.out.printf("Received GetNodeIndexReply: context=%d, nodeIndex=%d\n",
                msg.context, msg.nodeIndex);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception in getNodeIndexCallback: call=%s, reply=%d, context=%d\n",
                ex.getMethodName(), ex.getErrorCode(), ex.getCtxId());
        }
    };

    private static void testCallbackFacade() throws Exception {
        System.out.println("Testing CallbackJVppFacade");

        final JVppRegistry registry = new JVppRegistryImpl("CallbackFacadeTest");
        final JVppCore jvpp = new JVppCoreImpl();

        CallbackJVppCoreFacade jvppCallbackFacade = new CallbackJVppCoreFacade(registry, jvpp);
        System.out.println("Successfully connected to VPP");

        jvppCallbackFacade.showVersion(showVersionCallback1);
        jvppCallbackFacade.showVersion(showVersionCallback2);

        GetNodeIndex getNodeIndexRequest = new GetNodeIndex();
        getNodeIndexRequest.nodeName = "dummyNode".getBytes();
        jvppCallbackFacade.getNodeIndex(getNodeIndexRequest, getNodeIndexCallback);

        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        registry.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackFacade();
    }
}
