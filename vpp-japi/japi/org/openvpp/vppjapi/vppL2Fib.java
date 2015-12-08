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

public class vppL2Fib {
    public byte[] physAddress;
    public boolean staticConfig;
    public String outgoingInterface;
    public boolean filter;
    public boolean bridgedVirtualInterface;

    public vppL2Fib(byte[] _physAddress, boolean _staticConfig,
            String _outgoingInterface, boolean _filter,
            boolean _bridgedVirtualInterface) {
        physAddress = _physAddress;
        staticConfig = _staticConfig;
        outgoingInterface = _outgoingInterface;
        filter = _filter;
        bridgedVirtualInterface = _bridgedVirtualInterface;
    }
}
