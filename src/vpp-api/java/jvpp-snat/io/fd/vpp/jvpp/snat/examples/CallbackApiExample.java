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

package io.fd.vpp.jvpp.snat.examples;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.snat.JVppSnatImpl;
import io.fd.vpp.jvpp.snat.callback.SnatInterfaceAddDelFeatureCallback;
import io.fd.vpp.jvpp.snat.dto.SnatInterfaceAddDelFeature;
import io.fd.vpp.jvpp.snat.dto.SnatInterfaceAddDelFeatureReply;

public class CallbackApiExample {

    static class TestCallback implements SnatInterfaceAddDelFeatureCallback {

        @Override
        public void onSnatInterfaceAddDelFeatureReply(final SnatInterfaceAddDelFeatureReply msg) {
            System.out.printf("Received SnatInterfaceAddDelFeatureReply: context=%d%n",
                msg.context);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API for snat plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("SnatCallbackApiTest");
             final JVpp jvpp = new JVppSnatImpl()) {
            registry.register(jvpp, new TestCallback());

            System.out.println("Sending SnatInterfaceAddDelFeature request...");
            SnatInterfaceAddDelFeature request = new SnatInterfaceAddDelFeature();
            request.isAdd = 1;
            request.isInside = 1;
            request.swIfIndex = 1;
            final int result = jvpp.send(request);
            System.out.printf("SnatInterfaceAddDelFeature send result = %d%n", result);

            Thread.sleep(1000);

            System.out.println("Disconnecting...");
        }
    }
}
