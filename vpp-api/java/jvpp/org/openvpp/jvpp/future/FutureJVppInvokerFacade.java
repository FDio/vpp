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

package org.openvpp.jvpp.future;


import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.VppInvocationException;
import org.openvpp.jvpp.dto.ControlPing;
import org.openvpp.jvpp.dto.JVppDump;
import org.openvpp.jvpp.dto.JVppReply;
import org.openvpp.jvpp.dto.JVppReplyDump;
import org.openvpp.jvpp.dto.JVppRequest;
import org.openvpp.jvpp.notification.NotificationRegistryProvider;

/**
* Future facade on top of JVpp
*/
public class FutureJVppInvokerFacade extends NotificationRegistryProvider implements FutureJVppInvoker {

    private final JVpp jvpp;

    /**
     * Guarded by self
     */
    private final Map<Integer, CompletableFuture<? extends JVppReply<?>>> requests;

    public FutureJVppInvokerFacade(final JVpp jvpp,
                                   final Map<Integer, CompletableFuture<? extends JVppReply<?>>> requestMap) {
        this.jvpp =  Objects.requireNonNull(jvpp, "Null jvpp");
        // Request map represents the shared state between this facade and it's callback
        // where facade puts futures in and callback completes + removes them
        // TODO what if the call never completes ?
        this.requests = Objects.requireNonNull(requestMap, "Null requestMap");
    }

    protected final Map<Integer, CompletableFuture<? extends JVppReply<?>>> getRequests() {
        return this.requests;
    }

    // TODO use Optional in Future, java8

    @Override
    @SuppressWarnings("unchecked")
    public <REQ extends JVppRequest, REPLY extends JVppReply<REQ>> CompletionStage<REPLY> send(REQ req) throws VppInvocationException {
        synchronized(requests) {
            final int contextId = jvpp.send(req);

            final CompletableFuture<REPLY> replyCompletableFuture;
            if(req instanceof JVppDump) {
                replyCompletableFuture = (CompletableFuture<REPLY>) new CompletableDumpFuture<>(contextId);
            } else {
                replyCompletableFuture = new CompletableFuture<>();
            }

            requests.put(contextId, replyCompletableFuture);
            if(req instanceof JVppDump) {
                requests.put(jvpp.send(new ControlPing()), replyCompletableFuture);
            }
            return replyCompletableFuture;
        }
    }

    static final class CompletableDumpFuture<T extends JVppReplyDump<?, ?>> extends CompletableFuture<T> {
        // The reason why this is not final is the instantiation of ReplyDump DTOs
        // Their instantiation must be generated, so currently the DTOs are created in callback and set when first dump reponses
        // is handled in the callback.
        private T replyDump;
        private final long contextId;

        CompletableDumpFuture(final long contextId) {
            this.contextId = contextId;
        }

        long getContextId() {
            return contextId;
        }

        T getReplyDump() {
            return replyDump;
        }

        void setReplyDump(final T replyDump) {
            this.replyDump = replyDump;
        }
    }

    @Override
    public void close() throws Exception {
        // NOOP
    }
}
