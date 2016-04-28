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


/**
* Future facade on top of JVpp
*/
public class FutureJVppInvokerFacade implements FutureJVppInvoker {

    private final org.openvpp.jvpp.JVpp jvpp;
    private final java.util.Map<java.lang.Integer, java.util.concurrent.CompletableFuture<? extends org.openvpp.jvpp.dto.JVppReply<?>>> requests;

    public FutureJVppInvokerFacade(final org.openvpp.jvpp.JVpp jvpp,
                                   final java.util.Map<java.lang.Integer, java.util.concurrent.CompletableFuture<? extends org.openvpp.jvpp.dto.JVppReply<?>>> requestMap) {
        this.jvpp = jvpp;
        this.requests = requestMap;
    }

    // TODO use Optional in Future, java8

    @Override
    @SuppressWarnings("unchecked")
    public <REQ extends org.openvpp.jvpp.dto.JVppRequest, REPLY extends org.openvpp.jvpp.dto.JVppReply<REQ>> java.util.concurrent.Future<REPLY> send(REQ req) {
        final java.util.concurrent.CompletableFuture<REPLY> replyCompletableFuture;
        if(req instanceof org.openvpp.jvpp.dto.JVppDump) {
            replyCompletableFuture = (java.util.concurrent.CompletableFuture<REPLY>) new CompletableDumpFuture<>();
        } else {
            replyCompletableFuture = new java.util.concurrent.CompletableFuture<>();
        }

        synchronized(requests) {
            final int contextId = jvpp.send(req);
            requests.put(contextId, replyCompletableFuture);
            if(req instanceof org.openvpp.jvpp.dto.JVppDump) {
                ((CompletableDumpFuture) replyCompletableFuture).setContextId(contextId);
                requests.put(jvpp.send(new org.openvpp.jvpp.dto.ControlPing()), replyCompletableFuture);
            }
        }
        return replyCompletableFuture;
    }

    static final class CompletableDumpFuture<T extends org.openvpp.jvpp.dto.JVppReplyDump<?, ?>> extends java.util.concurrent.CompletableFuture<T> {
        private T replyDump;
        private long contextId;

        long getContextId() {
            return contextId;
        }

        void setContextId(final long contextId) {
            this.contextId = contextId;
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
