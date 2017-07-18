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

import static io.fd.vpp.jvpp.acl.examples.AclExpectedDumpData.verifyAclDump;
import static io.fd.vpp.jvpp.acl.examples.AclExpectedDumpData.verifyAclInterfaceList;
import static io.fd.vpp.jvpp.acl.examples.AclExpectedDumpData.verifyMacIpDump;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclAddRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclDelRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclDumpRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclInterfaceDeleteList;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclInterfaceListDumpRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendAclInterfaceSetAclList;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendMacIpAddRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendMacIpDelRequest;
import static io.fd.vpp.jvpp.acl.examples.AclTestRequests.sendMacIpDumpRequest;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.acl.JVppAclImpl;
import io.fd.vpp.jvpp.acl.future.FutureJVppAclFacade;

public class FutureApiExample {

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API for acl plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("macipAclAddTest");
             final FutureJVppAclFacade jvpp = new FutureJVppAclFacade(registry, new JVppAclImpl())) {

            // adds,dump and verifies  Mac-Ip acl
            sendMacIpAddRequest(jvpp);
            verifyMacIpDump(sendMacIpDumpRequest(jvpp).macipAclDetails.get(0));

            // adds,dumps and verifies Acl acl
            sendAclAddRequest(jvpp);
            verifyAclDump(sendAclDumpRequest(jvpp).aclDetails.get(0));

            // adds,dumps and verifies Interface for acl
            sendAclInterfaceSetAclList(jvpp);
            verifyAclInterfaceList(sendAclInterfaceListDumpRequest(jvpp).aclInterfaceListDetails.get(0));

            // deletes all created data
            sendAclInterfaceDeleteList(jvpp);
            sendAclDelRequest(jvpp);
            sendMacIpDelRequest(jvpp);

            System.out.println("Disconnecting...");
        }
    }
}
