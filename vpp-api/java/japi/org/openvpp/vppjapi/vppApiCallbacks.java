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

import java.io.IOException;
import org.openvpp.vppjapi.vppApi;

public abstract class vppApiCallbacks extends vppApi {
     public vppApiCallbacks(String clientName) throws IOException {
         super(clientName);
     }
/* Disabled!
 *
 * public abstract void interfaceDetails(
            int ifIndex, String interfaceName, int supIfIndex, byte[] physAddr,
            byte adminUp, byte linkUp, byte linkDuplex, byte linkSpeed,
            int subId, byte subDot1ad, byte subNumberOfTags, int subOuterVlanId, int subInnerVlanId,
            byte subExactMatch, byte subDefault, byte subOuterVlanIdAny, byte subInnerVlanIdAny,
            int vtrOp, int vtrPushDot1q, int vtrTag1, int vtrTag2);
 */

}
