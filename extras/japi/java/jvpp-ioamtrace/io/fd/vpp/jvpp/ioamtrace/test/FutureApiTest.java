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

package io.fd.vpp.jvpp.ioamtrace.test;


import io.fd.vpp.jvpp.Assertions;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.ioamtrace.JVppIoamtraceImpl;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileShowConfig;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileShowConfigReply;
import io.fd.vpp.jvpp.ioamtrace.future.FutureJVppIoamtraceFacade;

import java.util.concurrent.Future;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(io.fd.vpp.jvpp.ioamtrace.test.FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testCallbackApi(args);
    }

    private static void testCallbackApi(String[] args) throws Exception {
        LOG.info("Testing Java callback API for ioamtrace plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppIoamtraceFacade jvpp = new FutureJVppIoamtraceFacade(registry, new JVppIoamtraceImpl())) {
            LOG.info("Successfully connected to VPP");

            testTraceProfileShowConfig(jvpp);

            LOG.info("Disconnecting...");
        }
    }

    private static void testTraceProfileShowConfig(FutureJVppIoamtraceFacade jvpp) throws Exception {
        LOG.info("Sending TraceProfileShowConfig request...");
        final TraceProfileShowConfig request = new TraceProfileShowConfig();

        final Future<TraceProfileShowConfigReply> replyFuture = jvpp.traceProfileShowConfig(request).toCompletableFuture();
        final TraceProfileShowConfigReply reply = replyFuture.get();

        Assertions.assertNotNull(reply);
    }
}
