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

package io.fd.vpp.jvpp.core.examples;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.dto.LispAddDelAdjacency;
import io.fd.vpp.jvpp.core.dto.LispAddDelLocalEid;
import io.fd.vpp.jvpp.core.dto.LispAddDelLocatorSet;
import io.fd.vpp.jvpp.core.dto.LispAddDelRemoteMapping;
import io.fd.vpp.jvpp.core.dto.LispAdjacenciesGet;
import io.fd.vpp.jvpp.core.dto.LispAdjacenciesGetReply;
import io.fd.vpp.jvpp.core.dto.LispEnableDisable;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

/**
 * Tests lisp adjacency creation and read (custom vpe.api type support showcase).
 */
public class LispAdjacencyExample {

    private static final Logger LOG = Logger.getLogger(LispAdjacencyExample.class.getName());

    private static void enableLisp(final FutureJVppCoreFacade jvpp) throws ExecutionException, InterruptedException {
        final LispEnableDisable request = new LispEnableDisable();
        request.isEn = 1;
        jvpp.lispEnableDisable(request).toCompletableFuture().get();
        LOG.info("Lisp enabled successfully");
    }

    private static void addLocatorSet(final FutureJVppCoreFacade jvpp) throws ExecutionException, InterruptedException {
        final LispAddDelLocatorSet request = new LispAddDelLocatorSet();
        request.isAdd = 1;
        request.locatorSetName = "ls1".getBytes(StandardCharsets.UTF_8);
        jvpp.lispAddDelLocatorSet(request).toCompletableFuture().get();
        LOG.info("Locator set created successfully:" + request.toString());
    }

    private static void addLocalEid(final FutureJVppCoreFacade jvpp) throws ExecutionException, InterruptedException {
        final LispAddDelLocalEid request = new LispAddDelLocalEid();
        request.isAdd = 1;
        request.locatorSetName = "ls1".getBytes(StandardCharsets.UTF_8);
        request.eid = new byte[] {1, 2, 1, 10};
        request.eidType = 0; // ip4
        request.vni = 0;
        request.prefixLen = 32;
        jvpp.lispAddDelLocalEid(request).toCompletableFuture().get();
        LOG.info("Local EID created successfully:" + request.toString());
    }

    private static void addRemoteMapping(final FutureJVppCoreFacade jvpp)
        throws ExecutionException, InterruptedException {
        final LispAddDelRemoteMapping request = new LispAddDelRemoteMapping();
        request.isAdd = 1;
        request.vni = 0;
        request.eid = new byte[] {1, 2, 1, 20};
        request.eidLen = 32;
        request.rlocNum = 1;
        // FIXME!!!!
        //request.rlocs = new byte[] {1, 1, 1, 1, 2, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        jvpp.lispAddDelRemoteMapping(request).toCompletableFuture().get();
        LOG.info("Remote mapping created successfully:" + request.toString());
    }

    private static void addAdjacency(final FutureJVppCoreFacade jvpp) throws ExecutionException, InterruptedException {
        final LispAddDelAdjacency request = new LispAddDelAdjacency();
        request.isAdd = 1;
        request.leid = new byte[] {1, 2, 1, 10};
        request.leidLen = 32;
        request.reid = new byte[] {1, 2, 1, 20};
        request.reidLen = 32;
        request.eidType = 0; // ip4
        request.vni = 0;
        jvpp.lispAddDelAdjacency(request).toCompletableFuture().get();
        LOG.info("Lisp adjacency created successfully:" + request.toString());
    }

    private static void showAdjacencies(final FutureJVppCoreFacade jvpp)
        throws ExecutionException, InterruptedException {
        final LispAdjacenciesGetReply reply =
            jvpp.lispAdjacenciesGet(new LispAdjacenciesGet()).toCompletableFuture().get();
        LOG.info("Lisp adjacency received successfully:" + reply.toString());
    }

    private static void testAdjacency(final FutureJVppCoreFacade jvpp) throws Exception {
        enableLisp(jvpp);
        addLocatorSet(jvpp);
        addLocalEid(jvpp);
        addRemoteMapping(jvpp);
        addAdjacency(jvpp);
        showAdjacencies(jvpp);
    }

    private static void testFutureApi() throws Exception {
        LOG.info("Create lisp adjacency test");
        try (final JVppRegistry registry = new JVppRegistryImpl("LispAdjacencyExample");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl())) {
            LOG.info("Successfully connected to VPP");

            testAdjacency(jvppFacade);
            LOG.info("Disconnecting...");
        }
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
