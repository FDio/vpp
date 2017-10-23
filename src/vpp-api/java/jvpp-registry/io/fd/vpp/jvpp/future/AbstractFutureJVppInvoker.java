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


import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.VppInvocationException;
import io.fd.vpp.jvpp.dto.JVppDump;
import io.fd.vpp.jvpp.dto.JVppReply;
import io.fd.vpp.jvpp.dto.JVppReplyDump;
import io.fd.vpp.jvpp.dto.JVppRequest;

/**
 * Future facade on top of JVpp
 */
public abstract class AbstractFutureJVppInvoker implements FutureJVppInvoker {

    private final JVpp jvpp;
    private final JVppRegistry registry;

    /**
     * Guarded by self
     */
    private final Map<Integer, CompletableFuture<? extends JVppReply<?>>> requests;

    protected AbstractFutureJVppInvoker(final JVpp jvpp, final JVppRegistry registry,
                                        final Map<Integer, CompletableFuture<? extends JVppReply<?>>> requestMap) {
        this.jvpp =  Objects.requireNonNull(jvpp, "jvpp should not be null");
        this.registry =  Objects.requireNonNull(registry, "registry should not be null");
        // Request map represents the shared state between this facade and it's callback
        // where facade puts futures in and callback completes + removes them
        this.requests = Objects.requireNonNull(requestMap, "Null requestMap");
    }

    protected final Map<Integer, CompletableFuture<? extends JVppReply<?>>> getRequests() {
        synchronized (requests) {
            return requests;
        }
    }

    // TODO use Optional in Future, java8

    @Override
    @SuppressWarnings("unchecked")
    public <REQ extends JVppRequest, REPLY extends JVppReply<REQ>> CompletionStage<REPLY> send(REQ req) {
        try {
            // jvpp.send() can go to waiting state if sending queue is full, putting it into same
            // synchronization block as used by receiving part (synchronized(requests)) can lead
            // to deadlock between these two sides or at least slowing sending process by slow
            // reader
            final CompletableFuture<REPLY> replyCompletableFuture;
            final int contextId = jvpp.send(req);

            if(req instanceof JVppDump) {
                throw new IllegalArgumentException("Send with empty reply dump has to be used in case of dump calls");
            }

            synchronized(requests) {
                CompletableFuture<? extends JVppReply<?>> replyFuture = requests.get(contextId);
                if (replyFuture == null) {
                    // reply not yet received, put new future into map
                    replyCompletableFuture = new CompletableFuture<>();
                    requests.put(contextId, replyCompletableFuture);
                } else {
                    // reply already received (should be completed by reader),
                    // remove future from map and return it to caller
                    replyCompletableFuture = (CompletableFuture<REPLY>) replyFuture;
                    requests.remove(contextId);
                }
            }

            // TODO in case of timeouts/missing replies, requests from the map are not removed
            // consider adding cancel method, that would remove requests from the map and cancel
            // associated replyCompletableFuture

            return replyCompletableFuture;
        } catch (VppInvocationException ex) {
            final CompletableFuture<REPLY> replyCompletableFuture = new CompletableFuture<>();
            replyCompletableFuture.completeExceptionally(ex);
            return replyCompletableFuture;
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <REQ extends JVppRequest, REPLY extends JVppReply<REQ>, DUMP extends JVppReplyDump<REQ, REPLY>> CompletionStage<DUMP> send(
            REQ req, DUMP emptyReplyDump) {
      try {
          // jvpp.send() and registry.controlPing() can go to waiting state if sending queue is full,
          // putting it into same synchronization block as used by receiving part (synchronized(requests))
          // can lead to deadlock between these two sides or at least slowing sending process by slow reader
          final CompletableDumpFuture<DUMP> replyDumpFuture;
          final int contextId = jvpp.send(req);

          if(!(req instanceof JVppDump)) {
              throw new IllegalArgumentException("Send without empty reply dump has to be used in case of regular calls");
          }

          synchronized(requests) {
              CompletableFuture<? extends JVppReply<?>> replyFuture = requests.get(contextId);
              if (replyFuture == null) {
                  // reply not received yet, put new future to map
                  replyDumpFuture = new CompletableDumpFuture<>(contextId, emptyReplyDump);
                  requests.put(contextId, replyDumpFuture);
              } else {
                  // reply already received, save existing future
                  replyDumpFuture = (CompletableDumpFuture<DUMP>) replyFuture;
              }
          }

          final int pingId = registry.controlPing(jvpp.getClass());

          synchronized(requests) {
              if (requests.remove(pingId) == null) {
                  // reply not received yet, put future into map under pingId
                  requests.put(pingId, replyDumpFuture);
              } else {
                  // reply already received, complete future
                  // ping reply couldn't complete the future because it is not in map under
                  // ping id
                  replyDumpFuture.complete(replyDumpFuture.getReplyDump());
                  requests.remove(contextId);
              }
          }

          // TODO in case of timeouts/missing replies, requests from the map are not removed
          // consider adding cancel method, that would remove requests from the map and cancel
          // associated replyCompletableFuture

          return replyDumpFuture;
      } catch (VppInvocationException ex) {
          final CompletableFuture<DUMP> replyCompletableFuture = new CompletableFuture<>();
          replyCompletableFuture.completeExceptionally(ex);
          return replyCompletableFuture;
      }
    }

    public static final class CompletableDumpFuture<T extends JVppReplyDump<?, ?>> extends CompletableFuture<T> {
        private final T replyDump;
        private final int contextId;

        public CompletableDumpFuture(final int contextId, final T emptyDump) {
            this.contextId = contextId;
            this.replyDump = emptyDump;
        }

        public int getContextId() {
            return contextId;
        }

        public T getReplyDump() {
            return replyDump;
        }
    }

    @Override
    public void close() throws Exception {
        jvpp.close();
    }
}
