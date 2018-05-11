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

import io.fd.vpp.jvpp.acl.dto.AclAddReplace;
import io.fd.vpp.jvpp.acl.types.AclRule;

interface AclPerfTest {
    short MAX_PORT_NUMBER = (short) 65535;

    static AclAddReplace createAclAddRequest(final int aclSize) {
        AclAddReplace request = new AclAddReplace();
        request.aclIndex = -1; // define new one
        request.count = aclSize;
        request.r = createAclRules(aclSize);
        return request;
    }

    static AclRule[] createAclRules(final int aclSize) {
        final AclRule[] rules = new AclRule[aclSize];
        long ip = 0x01000000; // 1.0.0.0
        for (int i = 0; i < aclSize; ++i) {
            rules[i] = new AclRule();
            rules[i].isIpv6 = 0;
            rules[i].isPermit = 1;
            rules[i].srcIpAddr = getIp((int) ip++);
            rules[i].srcIpPrefixLen = 32;
            rules[i].dstIpAddr = getIp((int) ip++);
            rules[i].dstIpPrefixLen = 32;
            rules[i].dstportOrIcmpcodeFirst = 0;
            rules[i].dstportOrIcmpcodeLast = MAX_PORT_NUMBER;
            rules[i].srcportOrIcmptypeFirst = 0;
            rules[i].srcportOrIcmptypeLast = MAX_PORT_NUMBER;
            rules[i].proto = 17; // UDP
        }
        return rules;
    }

    static byte[] getIp(final int i) {
        int b1 = (i >> 24) & 0xff;
        int b2 = (i >> 16) & 0xff;
        int b3 = (i >> 8) & 0xff;
        int b4 = i & 0xff;
        return new byte[] {(byte) b1, (byte) b2, (byte) b3, (byte) b4};
    }

}
