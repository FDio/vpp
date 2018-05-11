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

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.acl.JVppAclImpl;
import io.fd.vpp.jvpp.acl.dto.AclAddReplace;
import io.fd.vpp.jvpp.acl.dto.AclAddReplaceReply;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceSetAclList;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceSetAclListReply;
import io.fd.vpp.jvpp.acl.future.FutureJVppAclFacade;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

public class FutureApiAclPerfTest {
    private static final Logger LOG = Logger.getLogger(FutureApiAclPerfTest.class.getName());

    public static void main(String[] args) throws Exception {
        final int aclCount = Integer.parseUnsignedInt(args[0]);
        if (aclCount <= 0 || aclCount > 255) {
            throw new IllegalArgumentException("Acl count should be in the range [1,255] but was " + aclCount);
        }
        final int aclSize = Integer.parseUnsignedInt(args[1]);
        final boolean assignOnInterface = Boolean.parseBoolean(args[2]);
        int trials = 5;
        if (args.length >= 4) {
            trials = Integer.parseUnsignedInt(args[3]);
        }
        futureApiAclPerfTest(aclCount, aclSize, trials, assignOnInterface);
    }

    private static void futureApiAclPerfTest(final int aclCount, final int aclSize, final int trials,
                                             final boolean assignOnInterface) throws Exception {
        LOG.info("Testing future ACL API performance");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiAclPerfTest");
             final FutureJVppAclFacade jvpp = new FutureJVppAclFacade(registry, new JVppAclImpl())) {
            final AclAddReplace acl = AclPerfTest.createAclAddRequest(aclSize);
            final AclInterfaceSetAclList aclList = AclPerfTest.createAclList(aclCount);
            for (int i = 0; i < trials; i++) {
                StopWatch stopWatch = new StopWatch(aclCount);
                LOG.info("Starting invocations trial " + i);
                stopWatch.reset();
                for (int x = 0; x < aclCount; x++) {
                    CompletableFuture<AclAddReplaceReply> reply = jvpp.aclAddReplace(acl).toCompletableFuture();
                    reply.thenRun(stopWatch::updateCounter);
                }

                // Assuming there is only single thread processing messages in VPP, so ACLs are created before
                // we assign them on the interface.
                if (assignOnInterface) {
                    CompletableFuture<AclInterfaceSetAclListReply> reply = jvpp.aclInterfaceSetAclList(aclList)
                        .toCompletableFuture();
                    reply.thenRun(stopWatch::stop).get();
                }

                // Finish time measurement, but do not update invocation counter
                long time = stopWatch.getTime();
                LOG.info(String.format("Invocations took %f ms (%f rules/s)", time / 1000000.0,
                    aclCount * aclSize * (1000000000.0 / time)));
            }

            Thread.sleep(1000);
            LOG.info("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    /**
     * Not thread safe, but should not be an issue, because JVPP reading part process only one message at a time.
     */
    private static class StopWatch {
        private final int desiredCount;
        private volatile int currentCount;

        private long startTime;
        private volatile long endTime;

        StopWatch(final int desiredCount) {
            this.desiredCount = desiredCount;
        }

        void reset() {
            startTime = System.nanoTime();
        }

        void updateCounter() {
            currentCount++;
            if (currentCount == desiredCount) {
                endTime = System.nanoTime();
            }
        }

        void stop() {
            endTime = System.nanoTime();
        }

        private long getTime() throws Exception {
            while (endTime == 0) {
                Thread.sleep(100);
            }
            return endTime-startTime;
        }
    }
}