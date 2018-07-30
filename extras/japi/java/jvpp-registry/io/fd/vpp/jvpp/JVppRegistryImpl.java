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

import static java.util.Objects.requireNonNull;

import io.fd.vpp.jvpp.callback.ControlPingCallback;
import io.fd.vpp.jvpp.callback.JVppCallback;
import io.fd.vpp.jvpp.dto.ControlPingReply;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default implementation of JVppRegistry.
 */
public final class JVppRegistryImpl implements JVppRegistry, ControlPingCallback {

    private static final Logger LOG = Logger.getLogger(JVppRegistryImpl.class.getName());

    private final VppJNIConnection connection;
    // Unguarded concurrent map, no race conditions expected on top of that
    private final Map<String, JVppCallback> pluginRegistry;
    // Guarded by self
    private final Map<Integer, ControlPingCallback> pingCalls;

    public JVppRegistryImpl(final String clientName) throws IOException {
        connection = new VppJNIConnection(clientName);
        connection.connect();
        pluginRegistry = new ConcurrentHashMap<>();
        pingCalls = new HashMap<>();
    }

    public JVppRegistryImpl(final String clientName, final String shmPrefix) throws IOException {
        connection = new VppJNIConnection(clientName, shmPrefix);
        connection.connect();
        pluginRegistry = new ConcurrentHashMap<>();
        pingCalls = new HashMap<>();
    }

    @Override
    public VppConnection getConnection() {
        return connection;
    }

    @Override
    public void register(final JVpp jvpp, final JVppCallback callback) {
        requireNonNull(jvpp, "jvpp should not be null");
        requireNonNull(callback, "Callback should not be null");
        final String name = jvpp.getClass().getName();
        if (pluginRegistry.containsKey(name)) {
            throw new IllegalArgumentException(
                String.format("Callback for plugin %s was already registered", name));
        }
        jvpp.init(this, callback, connection.getConnectionInfo().queueAddress,
            connection.getConnectionInfo().clientIndex);
        pluginRegistry.put(name, callback);
    }

    @Override
    public void unregister(final String name) {
        requireNonNull(name, "Plugin name should not be null");
        final JVppCallback previous = pluginRegistry.remove(name);
        assertPluginWasRegistered(name, previous);
    }

    @Override
    public JVppCallback get(final String name) {
        requireNonNull(name, "Plugin name should not be null");
        JVppCallback value = pluginRegistry.get(name);
        assertPluginWasRegistered(name, value);
        return value;
    }

    private native int controlPing0() throws VppInvocationException;

    @Override
    public int controlPing(final Class<? extends JVpp> clazz) throws VppInvocationException {
        connection.checkActive();
        final String name = clazz.getName();

        final ControlPingCallback callback = (ControlPingCallback) pluginRegistry.get(clazz.getName());
        assertPluginWasRegistered(name, callback);

        // controlPing0 is sending function and can go to waiting in case of e. g. full queue
        // because of that it cant be in same synchronization block as used by reply handler function
        int context = controlPing0();
        if (context < 0) {
            throw new VppInvocationException("controlPing", context);
        }

        synchronized (pingCalls) {
            // if callback is in map it's because reply was already received
            EarlyControlPingReply earlyReplyCallback = (EarlyControlPingReply) pingCalls.remove(context);
            if(earlyReplyCallback == null) {
                pingCalls.put(context, callback);
            } else {
                callback.onControlPingReply(earlyReplyCallback.getReply());
            }
        }

        return context;
    }

    @Override
    public void onControlPingReply(final ControlPingReply reply) {
        final ControlPingCallback callback;
        synchronized (pingCalls) {
            callback = pingCalls.remove(reply.context);
            if (callback == null) {
                // reply received early, because we don't know callback to call
                // we wrap the reply and let the sender to call it
                pingCalls.put(reply.context, new EarlyControlPingReply(reply));
                return;
            }
        }
        // pass the reply to the callback registered by the ping caller
        callback.onControlPingReply(reply);
    }

    @Override
    public void onError(final VppCallbackException ex) {
        final int ctxId = ex.getCtxId();
        final ControlPingCallback callback;

        synchronized (pingCalls) {
            callback = pingCalls.get(ctxId);
        }
        if (callback == null) {
            LOG.log(Level.WARNING, "No callback was registered for reply id={0} ", ctxId);
            return;
        }
        // pass the error to the callback registered by the ping caller
        callback.onError(ex);
    }

    private static void assertPluginWasRegistered(final String name, final JVppCallback value) {
        if (value == null) {
            throw new IllegalArgumentException(String.format("Callback for plugin %s is not registered", name));
        }
    }

    @Override
    public void close() throws Exception {
        connection.close();
    }

    private static class EarlyControlPingReply implements ControlPingCallback {

        private final ControlPingReply reply;

        public EarlyControlPingReply(final ControlPingReply reply) {
            this.reply = reply;
        }

        public ControlPingReply getReply() {
            return reply;
        }

        @Override
        public void onError(VppCallbackException ex) {
            throw new IllegalStateException("Calling onError in EarlyControlPingReply");
        }

        @Override
        public void onControlPingReply(ControlPingReply reply) {
            throw new IllegalStateException("Calling onControlPingReply in EarlyControlPingReply");
        }
    }
}
