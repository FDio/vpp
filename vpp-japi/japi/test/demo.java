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

import org.openvpp.vppjapi.*;

public class demo {

    public static void main (String[] args) throws Exception {
        org.openvpp.vppjapi.vppApi api = new org.openvpp.vppjapi.vppApi ("JavaTest", new vppApiCallbacks() {

            @Override
            public void getNodeIndexReply(final long contextId, final long retVal, final long nodeIndex) {
                System.err.println("SURPRISE");
            }
        });
        System.out.println("Connected OK...");


        System.err.printf("Invoked %d", api.getNodeIndex("1".getBytes()));

        for (int i = 0; i < 5; i++) {
            System.out.println("Sleeping");
            Thread.sleep(500);
        }
    }
}
