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
import org.openvpp.jvpp.callback.ControlPingCallback;
import org.openvpp.jvpp.dto.ControlPing;
import org.openvpp.jvpp.dto.ControlPingReply;

public class ControlPingTest {

    private static void testControlPing() throws Exception {
        System.out.println("Testing ControlPing using Java callback API");

        JVpp jvpp = new JVppImpl( new VppJNIConnection("ControlPingTest"));
        jvpp.connect( new ControlPingCallback() {
            @Override
            public void onControlPingReply(final ControlPingReply reply) {
                System.out.printf("Received ControlPingReply: context=%d, retval=%d, clientIndex=%d vpePid=%d\n",
                        reply.context, reply.retval, reply.clientIndex, reply.vpePid);
            }
        });
        System.out.println("Successfully connected to VPP");
        Thread.sleep(1000);

        jvpp.send(new ControlPing());

        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testControlPing();
    }
}
