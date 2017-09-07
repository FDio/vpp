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

package io.fd.vpp.jvpp.acl.examples;

import static io.fd.vpp.jvpp.acl.examples.AclTestData.createAclRules;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.createMacipRules;

import io.fd.vpp.jvpp.VppInvocationException;
import io.fd.vpp.jvpp.acl.dto.AclAddReplace;
import io.fd.vpp.jvpp.acl.dto.AclAddReplaceReply;
import io.fd.vpp.jvpp.acl.dto.AclDel;
import io.fd.vpp.jvpp.acl.dto.AclDelReply;
import io.fd.vpp.jvpp.acl.dto.AclDetailsReplyDump;
import io.fd.vpp.jvpp.acl.dto.AclDump;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceListDetailsReplyDump;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceListDump;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceSetAclList;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceSetAclListReply;
import io.fd.vpp.jvpp.acl.dto.MacipAclAdd;
import io.fd.vpp.jvpp.acl.dto.MacipAclAddReply;
import io.fd.vpp.jvpp.acl.dto.MacipAclAddReplace;
import io.fd.vpp.jvpp.acl.dto.MacipAclAddReplaceReply;
import io.fd.vpp.jvpp.acl.dto.MacipAclDel;
import io.fd.vpp.jvpp.acl.dto.MacipAclDelReply;
import io.fd.vpp.jvpp.acl.dto.MacipAclDetailsReplyDump;
import io.fd.vpp.jvpp.acl.dto.MacipAclDump;
import io.fd.vpp.jvpp.acl.future.FutureJVppAclFacade;
import java.util.concurrent.ExecutionException;

class AclTestRequests {

    static MacipAclDetailsReplyDump sendMacIpDumpRequest(final FutureJVppAclFacade jvpp)
            throws ExecutionException, InterruptedException {
        System.out.println("Sending MacipAclDump request...");
        MacipAclDetailsReplyDump dump = jvpp.macipAclDump(new MacipAclDump()).toCompletableFuture().get();
        System.out.println("MacipAclDump returned");
        return dump;
    }

    static void sendMacIpAddRequest(final FutureJVppAclFacade jvpp) throws InterruptedException, ExecutionException {
        final MacipAclAdd request = createMacIpAddRequest();
        System.out.printf("Sending MacipAclAdd request %s%n", request.toString());
        final MacipAclAddReply reply = jvpp.macipAclAdd(createMacIpAddRequest()).toCompletableFuture().get();
        System.out.printf("MacipAclAdd send result = %s%n", reply);
    }

    static void sendMacIpAddReplaceRequest(final FutureJVppAclFacade jvpp) throws InterruptedException, ExecutionException {
        final MacipAclAddReplace request = createMacIpAddReplaceRequest();
        System.out.printf("Sending MacipAclAddReplace request %s%n", request.toString());
        final MacipAclAddReplaceReply reply = jvpp.macipAclAddReplace(createMacIpAddReplaceRequest()).toCompletableFuture().get();
        System.out.printf("MacipAclAddReplace send result = %s%n", reply);
    }

    static void sendMacIpDelRequest(final FutureJVppAclFacade jvpp) throws InterruptedException, ExecutionException {
        final MacipAclDel request = new MacipAclDel();
        request.aclIndex = 0;
        System.out.printf("Sending MacipAclDel request %s%n", request.toString());
        final MacipAclDelReply reply = jvpp.macipAclDel(request).toCompletableFuture().get();
        System.out.printf("MacipAclDel send result = %s%n", reply);
    }

    static void sendAclAddRequest(final FutureJVppAclFacade jvpp) throws InterruptedException, ExecutionException {
        final AclAddReplace request = createAclAddRequest();
        System.out.printf("Sending AclAddReplace request %s%n", request.toString());
        final AclAddReplaceReply reply = jvpp.aclAddReplace(request).toCompletableFuture().get();
        System.out.printf("AclAddReplace send result = %s%n", reply);
    }

    static AclDetailsReplyDump sendAclDumpRequest(final FutureJVppAclFacade jvpp)
            throws InterruptedException, VppInvocationException, ExecutionException {
        System.out.println("Sending AclDump request...");
        final AclDetailsReplyDump dump = jvpp.aclDump(new AclDump()).toCompletableFuture().get();
        System.out.printf("AclDump send result = %s%n", dump);
        return dump;
    }

    static void sendAclDelRequest(final FutureJVppAclFacade jvpp) throws InterruptedException, ExecutionException {
        final AclDel request = new AclDel();
        request.aclIndex = 0;
        System.out.printf("Sending AclDel request %s%n", request.toString());
        final AclDelReply reply = jvpp.aclDel(request).toCompletableFuture().get();
        System.out.printf("AclDel send result = %s%n", reply);
    }

    static AclInterfaceListDetailsReplyDump sendAclInterfaceListDumpRequest(final FutureJVppAclFacade jvpp)
            throws InterruptedException, ExecutionException {
        final AclInterfaceListDump request = new AclInterfaceListDump();
        request.swIfIndex = 0;
        System.out.printf("Sending AclInterfaceListDump request %s%n", request.toString());
        final AclInterfaceListDetailsReplyDump dump = jvpp.aclInterfaceListDump(request).toCompletableFuture().get();
        System.out.printf("AclInterfaceListDump send result = %s%n", dump);
        return dump;
    }

    static void sendAclInterfaceSetAclList(final FutureJVppAclFacade jvpp)
            throws InterruptedException, ExecutionException {
        final AclInterfaceSetAclList request = new AclInterfaceSetAclList();
        request.count = 1;
        request.acls = new int[]{1};
        request.swIfIndex = 0;
        request.nInput = 0;
        System.out.printf("Sending AclInterfaceSetAclList request %s%n", request.toString());
        final AclInterfaceSetAclListReply reply = jvpp.aclInterfaceSetAclList(request).toCompletableFuture().get();
        System.out.printf("AclInterfaceSetAclList send result = %s%n", reply);
    }

    static void sendAclInterfaceDeleteList(final FutureJVppAclFacade jvpp)
            throws InterruptedException, ExecutionException {
        // uses same api but sets list to empty
        final AclInterfaceSetAclList request = new AclInterfaceSetAclList();
        request.count = 0;
        request.acls = new int[]{};
        request.swIfIndex = 0;
        request.nInput = 0;
        System.out.printf("Sending AclInterfaceSetAclList(Delete) request %s%n", request.toString());
        final AclInterfaceSetAclListReply reply = jvpp.aclInterfaceSetAclList(request).toCompletableFuture().get();
        System.out.printf("AclInterfaceSetAclList(Delete) send result = %s%n", reply);
    }

    private static MacipAclAdd createMacIpAddRequest() {
        MacipAclAdd request = new MacipAclAdd();

        request.count = 2;
        request.r = createMacipRules();
        return request;
    }

    private static MacipAclAddReplace createMacIpAddReplaceRequest() {
        MacipAclAddReplace request = new MacipAclAddReplace();

        request.count = 2;
        request.aclIndex = 0;
        request.r = createMacipRules();
        return request;
    }

    private static AclAddReplace createAclAddRequest() {
        AclAddReplace request = new AclAddReplace();

        request.aclIndex = -1;// to define new one
        request.count = 2;
        request.r = createAclRules();
        return request;
    }
}
