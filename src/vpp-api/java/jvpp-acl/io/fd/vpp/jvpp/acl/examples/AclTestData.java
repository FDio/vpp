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


import io.fd.vpp.jvpp.acl.types.AclRule;
import io.fd.vpp.jvpp.acl.types.MacipAclRule;

class AclTestData {

    static final byte[] FIRST_RULE_ADDRESS_AS_ARRAY = {-64, -88, 2, 1};
    static final byte[] FIRST_RULE_ADDRESS_2_AS_ARRAY = {-64, -88, 2, 3};
    static final byte[] SECOND_RULE_ADDRESS_AS_ARRAY =
            {32, 1, 13, -72, 10, 11, 18, -16, 0, 0, 0, 0, 0, 0, 0, 1};
    static final byte[] SECOND_RULE_ADDRESS_2_AS_ARRAY =
            {32, 1, 13, -72, 10, 11, 18, -16, 0, 0, 0, 0, 0, 0, 0, 1};
    static final byte[] FIRST_RULE_MAC = {11, 11, 11, 11, 11, 11};
    static final byte[] FIRST_RULE_MAC_MASK = {0, 0, 0, 0, 0, 0};
    static final byte[] SECOND_RULE_MAC = {11, 12, 11, 11, 12, 11};
    static final byte[] SECOND_RULE_MAC_MASK = {(byte) 170, 0, 0, 0, 0, 0};
    static final int FIRST_RULE_PREFIX = 32;
    static final int FIRST_RULE_PREFIX_2 = 24;
    static final int SECOND_RULE_PREFIX = 64;
    static final int SECOND_RULE_PREFIX_2 = 62;
    static final int FIRST_RULE_DST_ICMP_TYPE_START = 0;
    static final int FIRST_RULE_DST_ICMP_TYPE_END = 8;
    static final int FIRST_RULE_SRC_ICMP_TYPE_START = 1;
    static final int FIRST_RULE_SRC_ICMP_TYPE_END = 7;
    static final int ICMP_PROTOCOL = 1;
    static final int SECOND_RULE_DST_PORT_RANGE_START = 2000;
    static final int SECOND_RULE_DST_PORT_RANGE_END = 6000;
    static final int SECOND_RULE_SRC_PORT_RANGE_START = 400;
    static final int SECOND_RULE_SRC_PORT_RANGE_END = 2047;
    static final int UDP_PROTOCOL = 17;


    static MacipAclRule[] createMacipRules() {
        MacipAclRule ruleOne = new MacipAclRule();
        ruleOne.isIpv6 = 0;
        ruleOne.isPermit = 1;
        ruleOne.srcIpAddr = FIRST_RULE_ADDRESS_AS_ARRAY;
        ruleOne.srcIpPrefixLen = FIRST_RULE_PREFIX;
        ruleOne.srcMac = FIRST_RULE_MAC;
        ruleOne.srcMacMask = FIRST_RULE_MAC_MASK;// no mask

        MacipAclRule ruleTwo = new MacipAclRule();
        ruleTwo.isIpv6 = 1;
        ruleTwo.isPermit = 0;
        ruleTwo.srcIpAddr = SECOND_RULE_ADDRESS_AS_ARRAY;
        ruleTwo.srcIpPrefixLen = SECOND_RULE_PREFIX;
        ruleTwo.srcMac = SECOND_RULE_MAC;
        ruleTwo.srcMacMask = SECOND_RULE_MAC_MASK;

        return new MacipAclRule[]{ruleOne, ruleTwo};
    }

    static AclRule[] createAclRules() {
        AclRule ruleOne = new AclRule();

        ruleOne.isIpv6 = 0;
        ruleOne.isPermit = 1;
        ruleOne.srcIpAddr = FIRST_RULE_ADDRESS_AS_ARRAY;
        ruleOne.srcIpPrefixLen = FIRST_RULE_PREFIX;
        ruleOne.dstIpAddr = FIRST_RULE_ADDRESS_2_AS_ARRAY;
        ruleOne.dstIpPrefixLen = FIRST_RULE_PREFIX_2;
        ruleOne.dstportOrIcmpcodeFirst = FIRST_RULE_DST_ICMP_TYPE_START;
        ruleOne.dstportOrIcmpcodeLast = FIRST_RULE_DST_ICMP_TYPE_END;
        ruleOne.srcportOrIcmptypeFirst = FIRST_RULE_SRC_ICMP_TYPE_START;
        ruleOne.srcportOrIcmptypeLast = FIRST_RULE_SRC_ICMP_TYPE_END;
        ruleOne.proto = ICMP_PROTOCOL; //ICMP

        AclRule ruleTwo = new AclRule();
        ruleTwo.isIpv6 = 1;
        ruleTwo.isPermit = 0;
        ruleTwo.srcIpAddr = SECOND_RULE_ADDRESS_AS_ARRAY;
        ruleTwo.srcIpPrefixLen = SECOND_RULE_PREFIX;
        ruleTwo.dstIpAddr = SECOND_RULE_ADDRESS_2_AS_ARRAY;
        ruleTwo.dstIpPrefixLen = SECOND_RULE_PREFIX_2;
        ruleTwo.dstportOrIcmpcodeFirst = SECOND_RULE_DST_PORT_RANGE_START;
        ruleTwo.dstportOrIcmpcodeLast = SECOND_RULE_DST_PORT_RANGE_END;
        ruleTwo.srcportOrIcmptypeFirst = SECOND_RULE_SRC_PORT_RANGE_START;
        ruleTwo.srcportOrIcmptypeLast = SECOND_RULE_SRC_PORT_RANGE_END;
        ruleTwo.proto = UDP_PROTOCOL; //UDP

        return new AclRule[]{ruleOne, ruleTwo};
    }
}
