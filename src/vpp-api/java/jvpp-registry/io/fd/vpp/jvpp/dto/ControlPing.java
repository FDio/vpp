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

package io.fd.vpp.jvpp.dto;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.VppInvocationException;

/**
 * Represents request DTO for control_ping message.
 */
public final class ControlPing implements JVppRequest {

    @Override
    public int send(final JVpp jvpp) throws VppInvocationException {
        return jvpp.controlPing(this);
    }

}


