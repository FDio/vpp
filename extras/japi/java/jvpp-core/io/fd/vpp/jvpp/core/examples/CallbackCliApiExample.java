/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
import io.fd.vpp.jvpp.core.callback.CliInbandReplyCallback;
import io.fd.vpp.jvpp.core.dto.CliInband;
import io.fd.vpp.jvpp.core.dto.CliInbandReply;

import java.nio.charset.StandardCharsets;

public class CallbackCliApiExample {

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API for Cli with JVppRegistry");
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackCliApiExample");
             final JVpp jvpp = new JVppCoreImpl()) {
            registry.register(jvpp, new TestCallback());

            System.out.println("Sending CliInband request...");
            CliInband req = new CliInband();
            req.cmd = "create loopback interface";
            final int result = jvpp.send(req);
            System.out.printf("CliInband send result = %d%n", result);

            Thread.sleep(1000);
            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    static class TestCallback implements CliInbandReplyCallback {

        @Override
        public void onCliInbandReply(final CliInbandReply msg) {
            System.out.printf("Received CliInbandReply: context=%d, reply=%s", msg.context, msg.reply);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }
}
