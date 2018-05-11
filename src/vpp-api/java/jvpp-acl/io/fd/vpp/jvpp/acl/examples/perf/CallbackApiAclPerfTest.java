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

package io.fd.vpp.jvpp.acl.examples.perf;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.acl.JVppAclImpl;
import io.fd.vpp.jvpp.acl.callback.AclAddReplaceReplyCallback;
import io.fd.vpp.jvpp.acl.dto.AclAddReplace;
import io.fd.vpp.jvpp.acl.dto.AclAddReplaceReply;
import java.util.logging.Logger;

public class CallbackApiAclPerfTest {
    private static final Logger LOG = Logger.getLogger(CallbackApiAclPerfTest.class.getName());

    public static void main(String[] args) throws Exception {
        final int aclCount = Integer.parseUnsignedInt(args[0]);
        final int aclSize = Integer.parseUnsignedInt(args[1]);
        int trials = 5;
        if (args.length >= 3) {
            trials = Integer.parseUnsignedInt(args[2]);
        }
        testInvokeCounter(aclCount, aclSize, trials);
    }

    private static void testInvokeCounter(final int aclCount, final int aclSize, final int trials) throws Exception {
        LOG.info("Testing callback ACL API performance");
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackApiAclPerfTest");
             final JVpp jvpp = new JVppAclImpl()) {
            TestCallback callback = new TestCallback(aclCount);
            registry.register(jvpp, callback);

            final AclAddReplace request = AclPerfTest.createAclAddRequest(aclSize);
            for (int i = 0; i < trials; i++) {
                LOG.info("Starting invocations trial " + i);
                callback.reset();
                long time = System.nanoTime();
                for (int x = 0; x < aclCount; x++) {
                    jvpp.send(request);
                }
                long timeAfter = callback.getTime();
                long diff = timeAfter - time;
                LOG.info(String.format("Invocations took %f ms (%f rules/s)", diff / 1000000.0,
                    aclCount * aclSize * (1000000000.0 / diff)));
            }

            Thread.sleep(1000);
            LOG.info("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    static class TestCallback implements AclAddReplaceReplyCallback {

        private int replyCounter = 0;
        private int count;
        private long time = 0;
        private boolean stop = false;

        TestCallback(int count) throws Exception {
            this.count = count;
        }

        void reset() {
            replyCounter = 0;
            time = 0;
            stop = false;
        }

        /**
         * Actual method called from VPP.
         * Not thread safe but this is not an issue, because there's only one VPP thread processing replies.
         */
        @Override
        public void onAclAddReplaceReply(final AclAddReplaceReply msg) {
            if (stop) {
                return;
            }
            replyCounter++;
            if (replyCounter == count) {
                time = System.nanoTime();
            }
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n", ex.getMethodName(),
                ex.getCtxId(), ex.getErrorCode());
        }

        long getTime() throws Exception {
            while (time == 0) {
                Thread.sleep(1000);
            }
            return time;
        }
    }
}
