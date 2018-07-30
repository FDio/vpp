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

package io.fd.vpp.jvpp;

import io.fd.vpp.jvpp.callback.JVppCallback;
import io.fd.vpp.jvpp.dto.ControlPing;
import io.fd.vpp.jvpp.dto.JVppRequest;

/**
 * Base interface for plugin's Java API.
 */
public interface JVpp extends AutoCloseable {

    /**
     * Sends request to vpp.
     *
     * @param request request to be sent
     * @return unique identifer of message in message queue
     * @throws VppInvocationException when message could not be sent
     */
    int send(final JVppRequest request) throws VppInvocationException;

    /**
     * Initializes plugin's Java API.
     *
     * @param registry     plugin registry
     * @param callback     called by vpe.api message handlers
     * @param queueAddress address of vpp shared memory queue
     * @param clientIndex  vpp client identifier
     */
    void init(final JVppRegistry registry, final JVppCallback callback, final long queueAddress,
              final int clientIndex);

    /**
     * Sends control_ping message.
     *
     * @param controlPing request DTO
     * @return unique identifer of message in message queue
     * @throws VppInvocationException when message could not be sent
     */
    int controlPing(final ControlPing controlPing) throws VppInvocationException;
}
