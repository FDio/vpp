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

package org.openvpp.jvpp;

import java.io.IOException;

/**
 * Representation of a management connection to VPP.
 * Connection is initiated when instance is created, closed with close().
 */
public interface VppConnection extends AutoCloseable {

    /**
     * Open VppConnection for communication with VPP
     *
     * @param callback instance handling responses
     *
     * @throws IOException if connection is not established
     */
    void connect(final org.openvpp.jvpp.callback.JVppCallback callback) throws IOException;

    /**
     * Check if this instance connection is active.
     *
     * @throws IllegalStateException if this instance was disconnected.
     */
    void checkActive();

    /**
     * Closes Vpp connection.
     */
    @Override
    void close();
}
