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

package io.fd.vpp.jvpp.acl.test;

import io.fd.vpp.jvpp.Assertions;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.acl.JVppAclImpl;
import io.fd.vpp.jvpp.acl.dto.AclDetailsReplyDump;
import io.fd.vpp.jvpp.acl.dto.AclDump;
import io.fd.vpp.jvpp.acl.future.FutureJVppAclFacade;

import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(FutureApiTest.class.getName());

    public static void main(String[] args) throws Exception {
        testFutureApi(args);
    }

    private static void testFutureApi(String[] args) throws Exception {
        LOG.info("Testing Java future API for core plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest", args[0]);
             final FutureJVppAclFacade jvppFacade = new FutureJVppAclFacade(registry, new JVppAclImpl())) {
            LOG.info("Successfully connected to VPP");

            testAclDump(jvppFacade);

            LOG.info("Disconnecting...");
        }
    }

    private static void testAclDump(final FutureJVppAclFacade jvpp) throws Exception {
        LOG.info("Sending AclDump request...");
        final AclDump request = new AclDump();

        final CompletableFuture<AclDetailsReplyDump>
            replyFuture = jvpp.aclDump(request).toCompletableFuture();
        final AclDetailsReplyDump reply = replyFuture.get();

        Assertions.assertNotNull(reply);
    }


}
