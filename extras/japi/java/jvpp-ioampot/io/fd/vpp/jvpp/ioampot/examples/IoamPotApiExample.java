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

package io.fd.vpp.jvpp.ioampot.examples;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.ioampot.JVppIoampotImpl;
import io.fd.vpp.jvpp.ioampot.callback.PotProfileAddReplyCallback;
import io.fd.vpp.jvpp.ioampot.dto.PotProfileAdd;
import io.fd.vpp.jvpp.ioampot.dto.PotProfileAddReply;
import java.nio.charset.StandardCharsets;

public class IoamPotApiExample {

    static class IoamPotTestCallback implements PotProfileAddReplyCallback {

        @Override
        public void onPotProfileAddReply(final PotProfileAddReply reply) {
            System.out.printf("Received PotProfileAddReply reply: context=%d%n",
                reply.context);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }

    public static void main(String[] args) throws Exception {
        ioamPotTestApi();
    }

    private static void ioamPotTestApi() throws Exception {
        System.out.println("Testing Java API for ioam pot plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("ioamPotApiExample");
             final JVpp jvpp = new JVppIoampotImpl()) {
            registry.register(jvpp, new IoamPotTestCallback());

            System.out.println("Sending ioam pot profile add request...");
            PotProfileAdd request = new PotProfileAdd();
            request.id = 0;
            request.validator = 4;
            request.secretKey = 1;
            request.secretShare = 2;
            request.prime = 1234;
            request.maxBits = 53;
            request.lpc = 1234;
            request.polynomialPublic = 1234;
            request.listNameLen = (byte)"test pot profile".getBytes(StandardCharsets.UTF_8).length;
            request.listName = "test pot profile".getBytes(StandardCharsets.UTF_8);
            final int result = jvpp.send(request);
            System.out.printf("PotProfileAdd send result = %d%n", result);

            Thread.sleep(1000);

            System.out.println("Disconnecting...");
        }
    }
}
