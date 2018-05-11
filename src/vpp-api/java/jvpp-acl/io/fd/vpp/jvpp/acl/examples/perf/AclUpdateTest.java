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

import static io.fd.vpp.jvpp.acl.examples.perf.AclPerfTest.createSingletonAclList;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.acl.JVppAclImpl;
import io.fd.vpp.jvpp.acl.dto.AclAddReplace;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceSetAclList;
import io.fd.vpp.jvpp.acl.future.FutureJVppAclFacade;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

public class AclUpdateTest {
    private static final Logger LOG = Logger.getLogger(AclUpdateTest.class.getName());
    private static int DEFAULT_WARMUP_TRIAL_COUNT = 10;

    public static void main(String[] args) throws Exception {
        LOG.info("Testing synchronous ACL update performance using FutureJVppAclFacade");

        int aclSize = Integer.parseUnsignedInt(args[0]);
        LOG.info("ACL size: " + aclSize);

        int trailCount = Integer.parseUnsignedInt(args[1]);
        LOG.info("Number of trials: " + trailCount);

        int warmupTrailCount = DEFAULT_WARMUP_TRIAL_COUNT;
        if (args.length >= 3) {
            warmupTrailCount = Integer.parseUnsignedInt(args[2]);
        }
        LOG.info("Number of warmup trials: " + warmupTrailCount);

        aclUpdateTest(aclSize, trailCount, warmupTrailCount);
    }

    /**
     * Creates ACL of size acl_size using acl_add_replace,
     * then assigns it to local0 using acl_interface_set_acl_list.
     *
     * Then acl_add_replace is invoked synchronously trial_count times.
     * ACL used by acl_add_replace is not modified.
     * Average execution time of acl_add_replace invocation is reported.
     */
    private static void aclUpdateTest(int aclSize, int trailCount, final int warmupTrailCount) throws Exception {
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureJVppAclFacadeAclUpdateTest");
             final FutureJVppAclFacade jvpp = new FutureJVppAclFacade(registry, new JVppAclImpl())) {
            AclAddReplace acl = createAclAndSetForLocal0(jvpp, aclSize);
            updateAcl(jvpp, acl, warmupTrailCount);

            long startTime = System.nanoTime();
            updateAcl(jvpp, acl, trailCount);
            long endTime = System.nanoTime();
            double time = (double) (endTime - startTime) / trailCount;
            LOG.info(String.format("Average update time %f ms (%f rules/s)",
                time / 1000000, aclSize * (1000000000 / time)));
        }
        LOG.info("Disconnecting...");
    }

    /**
     * Sends acl_add_replace for given ACL. Waits for acl_add_replace_reply before sending another update.
     *
     * @param jvpp       Java API for ACLs in VPP
     * @param acl        ACL DTO
     * @param trailCount number of test trials
     */
    private static void updateAcl(final FutureJVppAclFacade jvpp, AclAddReplace acl, int trailCount)
        throws ExecutionException, InterruptedException {
        for (int i = 0; i < trailCount; ++i) {
            // Return value is not used in real application, so we skip it here as well
            jvpp.aclAddReplace(acl).toCompletableFuture().get();
        }
    }

    /**
     * Creates ACL of size aclSize and assigns it to local0 interface.
     *
     * @param jvpp    Java API for ACLs in VPP
     * @param aclSize size of ACL
     * @return ACL DTO with aclIndex set to value obtained from acl_add_replace_reply
     */
    private static AclAddReplace createAclAndSetForLocal0(FutureJVppAclFacade jvpp, int aclSize)
        throws ExecutionException, InterruptedException {
        AclAddReplace acl = AclPerfTest.createAclAddRequest(aclSize);
        int aclId = jvpp.aclAddReplace(acl).toCompletableFuture().get().aclIndex;
        AclInterfaceSetAclList aclList = createSingletonAclList(aclId);
        jvpp.aclInterfaceSetAclList(aclList).toCompletableFuture().get();
        acl.aclIndex = aclId;
        return acl;
    }
}