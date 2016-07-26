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

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.openvpp.jvpp.callback.JVppCallback;

public final class JVppRegistryImpl implements JVppRegistry {

    private final VppJNIConnection connection;
    private final ConcurrentMap<String, JVppCallback> map;

    public JVppRegistryImpl(final String clientName) throws IOException {
        connection = new VppJNIConnection(clientName);
        connection.connect();
        map = new ConcurrentHashMap<>();
    }

    @Override
    public void register(final JVpp jvpp, final JVppCallback callback) {
        requireNonNull(jvpp, "jvpp should not be null");
        requireNonNull(callback, "Callback should not be null");
        final String name = jvpp.getClass().getName();
        final JVppCallback previous = map.putIfAbsent(name, callback);
        if (previous != null) {
            throw new IllegalArgumentException(String.format("Callback for plugin %s was already registered", name));
        }
        jvpp.init(connection, callback, connection.getConnectionInfo().queueAddress, connection.getConnectionInfo().clientIndex);
    }

    @Override
    public void unregister(final String name) {
        requireNonNull(name, "Plugin name should not be null");
        final JVppCallback previous = map.remove(name);
        assertPluginWasRegistered(name, previous);
    }

    @Override
    public JVppCallback get(final String name) {
        requireNonNull(name, "Plugin name should not be null");
        JVppCallback value = map.get(name);
        assertPluginWasRegistered(name, value);
        return value;
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
}
