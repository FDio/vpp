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

package io.fd.vpp.jvpp.ioampot.test;


import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.ioampot.JVppIoampotImpl;
import io.fd.vpp.jvpp.ioampot.dto.PotProfileShowConfigDetailsReplyDump;
import io.fd.vpp.jvpp.ioampot.dto.PotProfileShowConfigDump;
import io.fd.vpp.jvpp.ioampot.future.FutureJVppIoampotFacade;

import java.util.concurrent.Future;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(io.fd.vpp.jvpp.ioampot.test.FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testCallbackApi(args);
    }

    private static void testCallbackApi(String[] args) throws Exception {
        LOG.info("Testing Java callback API for ioampot plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppIoampotFacade jvpp = new FutureJVppIoampotFacade(registry, new JVppIoampotImpl())) {
            LOG.info("Successfully connected to VPP");

            testPotProfileShowConfigDump(jvpp);

            LOG.info("Disconnecting...");
        }
    }

    private static void testPotProfileShowConfigDump(FutureJVppIoampotFacade jvpp) throws Exception {
        LOG.info("Sending PotProfileShowConfigDump request...");
        final PotProfileShowConfigDump request = new PotProfileShowConfigDump();

        final Future<PotProfileShowConfigDetailsReplyDump> replyFuture = jvpp.potProfileShowConfigDump(request).toCompletableFuture();
        final PotProfileShowConfigDetailsReplyDump reply = replyFuture.get();

        if (reply == null || reply.potProfileShowConfigDetails == null) {
            throw new IllegalStateException("Received null response for empty dump: " + reply);
        } else {
            LOG.info(
                    String.format(
                            "Received pot profile show config dump reply: %s",
                            reply.potProfileShowConfigDetails));
        }
    }
}
