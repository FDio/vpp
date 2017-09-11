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

package io.fd.vpp.jvpp.ioamtrace.examples;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.ioamtrace.future.FutureJVppIoamtraceFacade;
import io.fd.vpp.jvpp.ioamtrace.JVppIoamtraceImpl;
import io.fd.vpp.jvpp.ioamtrace.callback.TraceProfileAddReplyCallback;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileAdd;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileAddReply;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileShowConfig;
import io.fd.vpp.jvpp.ioamtrace.dto.TraceProfileShowConfigReply;

public class IoamTraceApiExample {

    static class IoamTraceTestCallback implements TraceProfileAddReplyCallback {

        @Override
        public void onTraceProfileAdd(final TraceProfileAddReply reply) {
            System.out.printf("Received TraceProfileAddReply reply: context=%d%n",
                reply.context);
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }
    }

    public static void main(String[] args) throws Exception {
        ioamTraceTestApi();
    }

    private static void ioamTraceTestApi() throws Exception {
        System.out.println("Testing Java API for ioam trace plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("ioamTraceApiTest");
             final JVpp jvpp = new JVppIoamtraceImpl()) {
	    FutureJVppIoamtraceFacade ioamtraceJvpp = new FutureJVppIoamtraceFacade(registry,jvpp);

            System.out.println("Sending ioam trace profile add request...");
            TraceProfileAdd request = new TraceProfileAdd();
            request.traceType = 0x1f;
            request.numElts = 4;
            request.nodeId = 1;
            request.traceTsp = 2;
            request.appData = 1234;
            final int result = jvpp.send(request);
            System.out.printf("TraceProfileAdd send result = %d%n", result);

            Thread.sleep(1000);

	    TraceProfileShowConfig showRequest = new TraceProfileShowConfig();
	    TraceProfileShowConfigReply reply = ioamtraceJvpp.traceProfileShowConfig(showRequest).toCompletableFuture().get();
            System.out.printf("TraceProfileShowConfig result = "+ reply.toString());

            System.out.println("Disconnecting...");
        }
    }
}
