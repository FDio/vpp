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

package io.fd.vpp.jvpp.core.examples;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.callback.ShowVersionReplyCallback;
import io.fd.vpp.jvpp.core.dto.*;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;

import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

public class FutureInvokeCounterExample {

    private static final Logger LOG = Logger.getLogger(FutureInvokeCounterExample.class.getName());
    private static int currentCount = 0;
    private static int desiredCount = 0;
    private static long timeAfter = 0;
    private static boolean stop = false;
    private static Runnable replyFc = () -> {
        if (stop) {
            return;
        }
        currentCount++;
        if(currentCount == desiredCount) {
            timeAfter = System.nanoTime();
        }
    };

    private static void reset() {
        currentCount = 0;
        timeAfter = 0;
        stop = false;
    }

    public static boolean stop() {
        stop = true;
        return false;
    }

    private static long getTime() throws Exception {
        while(timeAfter == 0) {
            LOG.info(String.format("Received %d replies", currentCount));
            Thread.sleep(1000);
        }
        return timeAfter;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            desiredCount =  Integer.parseUnsignedInt(args[0]);
            testInvokeCounter(true, Integer.parseUnsignedInt(args[1]));
        } else {
            testInvokeCounter(false, Integer.parseUnsignedInt(args[1]));
        }
    }

    private static void testInvokeCounter(boolean setCount, int diff) throws Exception {
        LOG.info("Testing callback API Invocation Counter");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureInvokeCounterExample");
             final FutureJVppCoreFacade jvpp = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {
            if (!setCount) {
                for(int i = 0; i < 5; i++) {
                    reset();
                    LOG.info("Starting invocation for 1sec");
                    long time = System.nanoTime();
                    do {
                        CompletableFuture<ShowVersionReply> replyFuture = jvpp.showVersion(new ShowVersion()).toCompletableFuture();
                        replyFuture.thenRun(replyFc);
                    } while (System.nanoTime() - time < 1000000000 || stop());
                    LOG.info(String.format("Invocation count within 1 second: %d", currentCount));
                }
            } else {
                for (int i = 0; i < 5; i++) {
                    LOG.info("Starting invocations");
                    reset();
                    long time = System.nanoTime();
                    for (int x = 0; x < desiredCount; x++) {
                        while (x - currentCount > diff);
                        //LOG.info(String.format("Sending request no. %d", x));
                        CompletableFuture<ShowVersionReply> replyFuture = jvpp.showVersion(new ShowVersion()).toCompletableFuture();
                        replyFuture.thenRun(replyFc);
                    }
                    LOG.info("Invocations send");
                    long timeAfter = getTime();
                    LOG.info(String.format("Invocations took %d ns (%f invocations/s)", timeAfter - time,
                            desiredCount * (1000000000.0/(timeAfter - time))));
                }
            }


            Thread.sleep(1000);
            LOG.info("Disconnecting...");
        }
        Thread.sleep(1000);
    }
}
