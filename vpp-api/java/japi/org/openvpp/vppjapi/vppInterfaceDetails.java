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

public final class vppInterfaceDetails {
    public final int ifIndex;
    public final String interfaceName;
    public final int supIfIndex;
    // FIXME: this is dangerous
    public final byte[] physAddr;
    public final byte adminUp;
    public final byte linkUp;
    public final byte linkDuplex;
    public final byte linkSpeed;
    public final int subId;
    public final byte subDot1ad;
    public final byte subNumberOfTags;
    public final int subOuterVlanId;
    public final int subInnerVlanId;
    public final byte subExactMatch;
    public final byte subDefault;
    public final byte subOuterVlanIdAny;
    public final byte subInnerVlanIdAny;
    public final int vtrOp;
    public final int vtrPushDot1q;
    public final int vtrTag1;
    public final int vtrTag2;
    public final int linkMtu;

    public vppInterfaceDetails(int ifIndex, String interfaceName, int supIfIndex, byte[] physAddr, byte adminUp,
            byte linkUp, byte linkDuplex, byte linkSpeed, int subId, byte subDot1ad, byte subNumberOfTags,
            int subOuterVlanId, int subInnerVlanId, byte subExactMatch, byte subDefault, byte subOuterVlanIdAny,
            byte subInnerVlanIdAny, int vtrOp, int vtrPushDot1q, int vtrTag1, int vtrTag2, int linkMtu)
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
        this.linkMtu = linkMtu;
    }
}
