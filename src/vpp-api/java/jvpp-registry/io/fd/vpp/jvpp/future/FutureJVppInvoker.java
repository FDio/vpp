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

package io.fd.vpp.jvpp.future;


import io.fd.vpp.jvpp.dto.JVppReply;
import io.fd.vpp.jvpp.dto.JVppReplyDump;
import io.fd.vpp.jvpp.dto.JVppRequest;

import java.util.concurrent.CompletionStage;
import io.fd.vpp.jvpp.notification.EventRegistryProvider;

/**
* Future facade on top of JVpp
*/
public interface FutureJVppInvoker extends EventRegistryProvider, AutoCloseable {

    /**
     * Invoke asynchronous operation on VPP
     *
     * @return CompletionStage with future result of an async VPP call
     * @throws io.fd.vpp.jvpp.VppInvocationException when send request failed with details
     */
    <REQ extends JVppRequest, REPLY extends JVppReply<REQ>> CompletionStage<REPLY> send(REQ req);


    /**
     * Invoke asynchronous dump operation on VPP
     *
     * @return CompletionStage with aggregated future result of an async VPP dump call
     * @throws io.fd.vpp.jvpp.VppInvocationException when send request failed with details
     */
    <REQ extends JVppRequest, REPLY extends JVppReply<REQ>, DUMP extends JVppReplyDump<REQ, REPLY>> CompletionStage<DUMP> send(
            REQ req, DUMP emptyReplyDump);
}
