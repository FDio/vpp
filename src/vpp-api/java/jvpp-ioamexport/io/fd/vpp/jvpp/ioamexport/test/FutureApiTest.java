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

package io.fd.vpp.jvpp.ioamexport.test;


import io.fd.vpp.jvpp.Assertions;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.ioamexport.JVppIoamexportImpl;
import io.fd.vpp.jvpp.ioamexport.dto.IoamExportIp6EnableDisable;
import io.fd.vpp.jvpp.ioamexport.dto.IoamExportIp6EnableDisableReply;
import io.fd.vpp.jvpp.ioamexport.future.FutureJVppIoamexportFacade;

import java.util.concurrent.Future;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testCallbackApi(args);
    }

    private static void testCallbackApi(String[] args) throws Exception {
        LOG.info("Testing Java callback API for ioamexport plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppIoamexportFacade jvpp = new FutureJVppIoamexportFacade(registry, new JVppIoamexportImpl())) {
            LOG.info("Successfully connected to VPP");

            testIoamExportIp6EnableDisable(jvpp);

            LOG.info("Disconnecting...");
        }
    }

    private static void testIoamExportIp6EnableDisable(FutureJVppIoamexportFacade jvpp) throws Exception {
        LOG.info("Sending IoamExportIp6EnableDisable request...");
        final IoamExportIp6EnableDisable request = new IoamExportIp6EnableDisable();

        final Future<IoamExportIp6EnableDisableReply> replyFuture = jvpp.ioamExportIp6EnableDisable(request).toCompletableFuture();
        final IoamExportIp6EnableDisableReply reply = replyFuture.get();

        Assertions.assertNotNull(reply);
    }
}
