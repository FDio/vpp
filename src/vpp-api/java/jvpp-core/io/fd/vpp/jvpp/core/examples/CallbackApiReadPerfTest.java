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

import java.util.logging.Logger;

public class CallbackApiReadPerfTest {

    private static final Logger LOG = Logger.getLogger(CallbackApiReadPerfTest.class.getName());
    private static final ShowVersion REQUEST = new ShowVersion();

    /**
     *
     * @param args - for running for one sec requires no parameter
     *             - for running for set amount of requests requires one parameters, desired REQUEST amount
     * @throws Exception if arguments aren't String representations of numbers
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            testInvokeCounter(true, Integer.parseUnsignedInt(args[0]));
        } else {
            testInvokeCounter(false, 0);
        }
    }

    /**
     *
     * @param setCount true = run with set amount of requests, false = run for 1 sec
     * @param count number of request with which test should be run
     * @throws Exception
     */
    private static void testInvokeCounter(boolean setCount, int count) throws Exception {
        LOG.info("Testing callback API Invocation Counter");
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackApiReadPerfTest");
             final JVpp jvpp = new JVppCoreImpl()) {
            TestCallback callback = new TestCallback(count);
            registry.register(jvpp, callback);
            if (!setCount) {
                for(int i = 0; i < 5; i++) {
                    callback.reset();
                    LOG.info("Starting invocation for 1sec");
                    long time = System.nanoTime();
                    do {
                        jvpp.send(REQUEST);
                    } while (System.nanoTime() - time < 1000000000 || callback.stop());
                    int replyCount =  callback.getReplyCounter();
                    LOG.info(String.format("Invocation count within 1 second: %d", replyCount));
                }
            } else {
                for (int i = 0; i < 5; i++) {
                    LOG.info("Starting invocations");
                    callback.reset();
                    long time = System.nanoTime();
                    for (int x = 0; x < count; x++) {
                        jvpp.send(REQUEST);
                    }
                    long timeAfter = callback.getTime();
                    LOG.info(String.format("Invocations took %d ns (%f invocations/s)", timeAfter - time,
                            count * (1000000000.0/(timeAfter - time))));
                }
            }


            Thread.sleep(1000);
            LOG.info("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    static class TestCallback implements ShowVersionReplyCallback {

        private int replyCounter = 0;
        private int count;
        private long time = 0;
        private boolean stop = false;

        public TestCallback(int count) throws Exception {
            this.count = count;
        }

        public int getReplyCounter() {
            return replyCounter;
        }

        public void reset() {
            replyCounter = 0;
            time = 0;
            stop = false;
        }

        public boolean stop() {
            this.stop = true;
            return false;
        }

        /* actual method called from VPP
           not thread safe but since there's only one VPP thread listening for requests and calling
           this method it's OK
         */
        @Override
        public void onShowVersionReply(final ShowVersionReply msg) {
            if (stop) {
                return;
            }
            replyCounter++;
            if (replyCounter == count ) {
                time = System.nanoTime();
            }
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }

        public long getTime() throws Exception {
            while(time == 0) {
                Thread.sleep(1000);
            }
            return time;
        }
    }
}
