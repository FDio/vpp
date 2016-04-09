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

public final class vppL2Fib {
    // FIXME: this is dangerous
    public final byte[] physAddress;
    public final boolean staticConfig;
    public final String outgoingInterface;
    public final boolean filter;
    public final boolean bridgedVirtualInterface;

    public vppL2Fib(byte[] physAddress, boolean staticConfig,
            String outgoingInterface, boolean filter,
            boolean bridgedVirtualInterface) {
        this.physAddress = physAddress;
        this.staticConfig = staticConfig;
        this.outgoingInterface = outgoingInterface;
        this.filter = filter;
        this.bridgedVirtualInterface = bridgedVirtualInterface;
    }
}
