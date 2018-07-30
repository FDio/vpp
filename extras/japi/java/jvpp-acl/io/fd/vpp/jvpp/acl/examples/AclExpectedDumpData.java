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


import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_ADDRESS_2_AS_ARRAY;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_ADDRESS_AS_ARRAY;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_DST_ICMP_TYPE_END;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_DST_ICMP_TYPE_START;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_MAC;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_MAC_MASK;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_PREFIX;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_PREFIX_2;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_SRC_ICMP_TYPE_END;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.FIRST_RULE_SRC_ICMP_TYPE_START;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.ICMP_PROTOCOL;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_ADDRESS_2_AS_ARRAY;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_ADDRESS_AS_ARRAY;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_DST_PORT_RANGE_END;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_DST_PORT_RANGE_START;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_MAC;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_MAC_MASK;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_PREFIX;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_PREFIX_2;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_SRC_PORT_RANGE_END;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.SECOND_RULE_SRC_PORT_RANGE_START;
import static io.fd.vpp.jvpp.acl.examples.AclTestData.UDP_PROTOCOL;

import io.fd.vpp.jvpp.acl.dto.AclDetails;
import io.fd.vpp.jvpp.acl.dto.AclInterfaceListDetails;
import io.fd.vpp.jvpp.acl.dto.MacipAclDetails;
import io.fd.vpp.jvpp.acl.types.AclRule;
import io.fd.vpp.jvpp.acl.types.MacipAclRule;
import java.util.Arrays;

class AclExpectedDumpData {

    static void verifyMacIpDump(final MacipAclDetails macipAclDetails) {
        // asserting data create by previous call
        assertEquals(0, macipAclDetails.aclIndex);
        assertEquals(2, macipAclDetails.count);

        final MacipAclRule currentIpv4Rule = macipAclDetails.r[0];
        final MacipAclRule currentIpv6Rule = macipAclDetails.r[1];

        // Comparing one property at the time to better pointer if something is wrong
        //Ipv4 rule
        assertEquals(0, currentIpv4Rule.isIpv6);
        assertEquals(1, currentIpv4Rule.isPermit);

        // cutting expected ipv4 to 4 bytes,vpp sends it as 16 always
        assertArrays(FIRST_RULE_ADDRESS_AS_ARRAY, Arrays.copyOfRange(currentIpv4Rule.srcIpAddr, 0, 4));
        assertEquals(FIRST_RULE_PREFIX, currentIpv4Rule.srcIpPrefixLen);
        assertArrays(FIRST_RULE_MAC, currentIpv4Rule.srcMac);
        assertArrays(FIRST_RULE_MAC_MASK, currentIpv4Rule.srcMacMask);

        //Ipv6 rule
        assertEquals(1, currentIpv6Rule.isIpv6);
        assertEquals(0, currentIpv6Rule.isPermit);
        assertArrays(SECOND_RULE_ADDRESS_AS_ARRAY, currentIpv6Rule.srcIpAddr);
        assertEquals(SECOND_RULE_PREFIX, currentIpv6Rule.srcIpPrefixLen);
        assertArrays(SECOND_RULE_MAC, currentIpv6Rule.srcMac);
        assertArrays(SECOND_RULE_MAC_MASK, currentIpv6Rule.srcMacMask);
    }

    static void verifyAclDump(final AclDetails aclDetails) {
        assertEquals(0, aclDetails.aclIndex);
        assertEquals(2, aclDetails.count);

        final AclRule currentIpv4Rule = aclDetails.r[0];
        final AclRule currentIpv6Rule = aclDetails.r[1];

        // Comparing one property at the time to better pointer if something is wrong
        //Ipv4 rule
        assertEquals(0, currentIpv4Rule.isIpv6);
        assertEquals(1, currentIpv4Rule.isPermit);

        // cutting expected ipv4 to 4 bytes,vpp sends it as 16 always
        assertArrays(FIRST_RULE_ADDRESS_AS_ARRAY, Arrays.copyOfRange(currentIpv4Rule.srcIpAddr, 0, 4));
        assertEquals(FIRST_RULE_PREFIX, currentIpv4Rule.srcIpPrefixLen);
        assertArrays(FIRST_RULE_ADDRESS_2_AS_ARRAY, Arrays.copyOfRange(currentIpv4Rule.dstIpAddr, 0, 4));
        assertEquals(FIRST_RULE_PREFIX_2, currentIpv4Rule.dstIpPrefixLen);

        assertEquals(ICMP_PROTOCOL, currentIpv4Rule.proto);
        assertEquals(FIRST_RULE_SRC_ICMP_TYPE_START, currentIpv4Rule.srcportOrIcmptypeFirst);
        assertEquals(FIRST_RULE_SRC_ICMP_TYPE_END, currentIpv4Rule.srcportOrIcmptypeLast);
        assertEquals(FIRST_RULE_DST_ICMP_TYPE_START, currentIpv4Rule.dstportOrIcmpcodeFirst);
        assertEquals(FIRST_RULE_DST_ICMP_TYPE_END, currentIpv4Rule.dstportOrIcmpcodeLast);

        assertArrays(SECOND_RULE_ADDRESS_AS_ARRAY, currentIpv6Rule.srcIpAddr);
        assertEquals(SECOND_RULE_PREFIX, currentIpv6Rule.srcIpPrefixLen);
        assertArrays(SECOND_RULE_ADDRESS_2_AS_ARRAY, currentIpv6Rule.dstIpAddr);
        assertEquals(SECOND_RULE_PREFIX_2, currentIpv6Rule.dstIpPrefixLen);

        assertEquals(UDP_PROTOCOL, currentIpv6Rule.proto);
        assertEquals(SECOND_RULE_SRC_PORT_RANGE_START, currentIpv6Rule.srcportOrIcmptypeFirst);
        assertEquals(SECOND_RULE_SRC_PORT_RANGE_END, currentIpv6Rule.srcportOrIcmptypeLast);
        assertEquals(SECOND_RULE_DST_PORT_RANGE_START, currentIpv6Rule.dstportOrIcmpcodeFirst);
        assertEquals(SECOND_RULE_DST_PORT_RANGE_END, currentIpv6Rule.dstportOrIcmpcodeLast);
    }

    static void verifyAclInterfaceList(final AclInterfaceListDetails aclInterfaceListDetails) {
        assertEquals(1, aclInterfaceListDetails.count);
        assertEquals(1, aclInterfaceListDetails.acls[0]);
        assertEquals(0, aclInterfaceListDetails.nInput);
        assertEquals(0, aclInterfaceListDetails.swIfIndex);
    }

    private static void assertArrays(final byte[] expected, final byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new IllegalArgumentException(
                    String.format("Expected[%s]/Actual[%s]", Arrays.toString(expected), Arrays.toString(actual)));
        }
    }

    private static void assertEquals(final int expected, final int actual) {
        if (expected != actual) {
            throw new IllegalArgumentException(String.format("Expected[%s]/Actual[%s]", expected, actual));
        }
    }
}
