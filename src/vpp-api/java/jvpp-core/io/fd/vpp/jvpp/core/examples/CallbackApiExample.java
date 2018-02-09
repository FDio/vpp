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
import io.fd.vpp.jvpp.core.callback.SwInterfaceSetFlagsReplyCallback;
import io.fd.vpp.jvpp.core.dto.SwInterfaceSetFlags;
import io.fd.vpp.jvpp.core.dto.SwInterfaceSetFlagsReply;
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

            System.out.println("Sending SwInterfaceSetFlags request...");
            final SwInterfaceSetFlags swInterfaceSetFlagsRequest = new SwInterfaceSetFlags();
            swInterfaceSetFlagsRequest.swIfIndex = 0;
            swInterfaceSetFlagsRequest.adminUpDown = 1;
            final int result = jvpp.send(swInterfaceSetFlagsRequest);
            System.out.printf("SwInterfaceSetFlags send result = %d%n", result);

            Thread.sleep(1000);
            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    static class TestCallback implements SwInterfaceSetFlagsReplyCallback {

        @Override
        public void onSwInterfaceSetFlagsReply(final SwInterfaceSetFlagsReply msg) {
            System.out.printf("Received SwInterfaceSetFlagsReply: %s%n", msg);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }
}
