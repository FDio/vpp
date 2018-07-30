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

import java.util.Objects;

/**
 * Represents reply DTO for control_ping message.
 */
public final class ControlPingReply implements JVppReply<ControlPing> {

    public int context;
    public int clientIndex;
    public int vpePid;

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ControlPingReply that = (ControlPingReply) o;
        return context == that.context &&
                clientIndex == that.clientIndex &&
                vpePid == that.vpePid;
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, clientIndex, vpePid);
    }

    @Override
    public String toString() {
        return "ControlPingReply{" +
                "context=" + context +
                ", clientIndex=" + clientIndex +
                ", vpePid=" + vpePid +
                '}';
    }
}

