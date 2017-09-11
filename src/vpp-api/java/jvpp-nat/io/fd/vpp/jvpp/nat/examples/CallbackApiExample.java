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

package io.fd.vpp.jvpp.nat.examples;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.nat.JVppNatImpl;
import io.fd.vpp.jvpp.nat.callback.Nat44InterfaceAddDelFeatureReplyCallback;
import io.fd.vpp.jvpp.nat.dto.Nat44InterfaceAddDelFeature;
import io.fd.vpp.jvpp.nat.dto.Nat44InterfaceAddDelFeatureReply;

public class CallbackApiExample {

    static class TestCallback implements Nat44InterfaceAddDelFeatureReplyCallback {

        @Override
        public void onNat44InterfaceAddDelFeature(final Nat44InterfaceAddDelFeatureReply msg) {
            System.out.printf("Received Nat44InterfaceAddDelFeatureReply: context=%d%n",
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
        System.out.println("Testing Java callback API for nat plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("NatCallbackApiTest");
             final JVpp jvpp = new JVppNatImpl()) {
            registry.register(jvpp, new TestCallback());

            System.out.println("Sending Nat44InterfaceAddDelFeature request...");
            Nat44InterfaceAddDelFeature request = new Nat44InterfaceAddDelFeature();
            request.isAdd = 1;
            request.isInside = 1;
            request.swIfIndex = 1;
            final int result = jvpp.send(request);
            System.out.printf("Nat44InterfaceAddDelFeature send result = %d%n", result);

            Thread.sleep(1000);

            System.out.println("Disconnecting...");
        }
    }
}
