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
import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.JVppCallback;
import org.openvpp.jvpp.callback.ShowVersionCallback;
import org.openvpp.jvpp.callfacade.CallbackJVppFacade;
import org.openvpp.jvpp.callfacade.CallbackJVppFacadeCallback;

/**
 * CallbackJVppFacade together with CallbackJVppFacadeCallback allow for setting different callback for each request.
 * This is more convenient than the approach shown in CallbackApiTest.
 */
public class CallbackJVppFacadeTest {

    private static ShowVersionCallback showVersionCallback1 = msg ->
            System.out.printf("ShowVersionCallback1 received ShowVersionReply: context=%d, retval=%d, program=%s," +
                            "version=%s, buildDate=%s, buildDirectory=%s\n", msg.context, msg.retval, new String(msg.program),
                    new String(msg.version), new String(msg.buildDate), new String(msg.buildDirectory));

    private static ShowVersionCallback showVersionCallback2 = msg ->
            System.out.printf("ShowVersionCallback2 received ShowVersionReply: context=%d, retval=%d, program=%s," +
                            "version=%s, buildDate=%s, buildDirectory=%s\n", msg.context, msg.retval, new String(msg.program),
                    new String(msg.version), new String(msg.buildDate), new String(msg.buildDirectory));

    private static void testCallbackFacade() throws Exception {
        System.out.println("Testing CallbackJVppFacade");

        final Map<Integer, JVppCallback> callbackMap = new HashMap<>();
        JVpp impl = new JVppImpl(VppJNIConnection.create("CallbackApiTest", new CallbackJVppFacadeCallback(callbackMap)));
        CallbackJVppFacade jvpp = new CallbackJVppFacade(impl, callbackMap);
        System.out.println("Successfully connected to VPP");

        jvpp.showVersion(showVersionCallback1);
        jvpp.showVersion(showVersionCallback2);


        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        impl.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackFacade();
    }
}
