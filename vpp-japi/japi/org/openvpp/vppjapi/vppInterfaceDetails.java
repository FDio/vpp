/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

package org.openvpp.vppjapi;

public class vppInterfaceDetails {
    public int ifIndex;
    public String interfaceName;
    public int supIfIndex;
    public byte[] physAddr;
    public byte adminUp;
    public byte linkUp;
    public byte linkDuplex;
    public byte linkSpeed;
    public int subId;
    public byte subDot1ad;
    public byte subNumberOfTags;
    public int subOuterVlanId;
    public int subInnerVlanId;
    public byte subExactMatch;
    public byte subDefault;
    public byte subOuterVlanIdAny;
    public byte subInnerVlanIdAny;
    public int vtrOp;
    public int vtrPushDot1q;
    public int vtrTag1;
    public int vtrTag2;

    public vppInterfaceDetails(int ifIndex, String interfaceName, int supIfIndex, byte[] physAddr, byte adminUp,
            byte linkUp, byte linkDuplex, byte linkSpeed, int subId, byte subDot1ad, byte subNumberOfTags,
            int subOuterVlanId, int subInnerVlanId, byte subExactMatch, byte subDefault, byte subOuterVlanIdAny,
            byte subInnerVlanIdAny, int vtrOp, int vtrPushDot1q, int vtrTag1, int vtrTag2)
    {
        this.ifIndex = ifIndex;
        this.interfaceName = interfaceName;
        this.supIfIndex = supIfIndex;
        this.physAddr = physAddr;
        this.adminUp = adminUp;
        this.linkUp = linkUp;
        this.linkDuplex = linkDuplex;
        this.linkSpeed = linkSpeed;
        this.subId = subId;
        this.subDot1ad = subDot1ad;
        this.subNumberOfTags = subNumberOfTags;
        this.subOuterVlanId = subOuterVlanId;
        this.subInnerVlanId = subInnerVlanId;
        this.subExactMatch = subExactMatch;
        this.subDefault = subDefault;
        this.subOuterVlanIdAny = subOuterVlanIdAny;
        this.subInnerVlanIdAny = subInnerVlanIdAny;
        this.vtrOp = vtrOp;
        this.vtrPushDot1q = vtrPushDot1q;
        this.vtrTag1 = vtrTag1;
        this.vtrTag2 = vtrTag2;
    }
}
