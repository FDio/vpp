/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

package io.fd.vpp.jvpp;

import io.fd.vpp.jvpp.callback.ControlPingCallback;
import io.fd.vpp.jvpp.dto.ControlPing;
import io.fd.vpp.jvpp.dto.ControlPingReply;

public abstract class AbstractCallbackApiTest {

    private static int receivedPingCount = 0;
    private static int errorPingCount = 0;

    public static void testControlPing(String shm_prefix, JVpp jvpp) throws Exception {
        try (JVppRegistry registry = new JVppRegistryImpl("CallbackApiTest", shm_prefix)) {

            registry.register(jvpp, new ControlPingCallback() {
                @Override
                public void onControlPingReply(final ControlPingReply reply) {
                    System.out.printf("Received ControlPingReply: %s%n", reply);
                    receivedPingCount++;
                }

                @Override
                public void onError(VppCallbackException ex) {
                    System.out.printf("Received onError exception: call=%s, reply=%d, context=%d ", ex.getMethodName(),
                            ex.getErrorCode(), ex.getCtxId());
                    errorPingCount++;
                }

            });
            System.out.println("Successfully connected to VPP");
            Thread.sleep(1000);

            System.out.println("Sending control ping using JVppRegistry");
            registry.controlPing(jvpp.getClass());

            Thread.sleep(2000);

            System.out.println("Sending control ping using JVpp plugin");
            jvpp.send(new ControlPing());

            Thread.sleep(2000);
            System.out.println("Disconnecting...");
            Assertions.assertEquals(2, receivedPingCount);
            Assertions.assertEquals(0, errorPingCount);
        }
    }
}
