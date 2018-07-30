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

/**
 * Manages VPP connection and stores plugin callbacks.
 */
public interface JVppRegistry extends AutoCloseable {

    /**
     * Vpp connection managed by the registry.
     *
     * @return representation of vpp connection
     */
    VppConnection getConnection();

    /**
     * Registers callback and initializes Java API for given plugin.
     *
     * @param jvpp     plugin name
     * @param callback callback provided by the plugin
     * @throws NullPointerException     if name or callback is null
     * @throws IllegalArgumentException if plugin was already registered
     */
    void register(final JVpp jvpp, final JVppCallback callback);

    /**
     * Unregisters callback for the given plugin.
     *
     * @param name plugin name
     * @throws NullPointerException     if name is null
     * @throws IllegalArgumentException if plugin was not registered
     */
    void unregister(final String name);

    /**
     * Returns callback registered for the plugin.
     *
     * @param name plugin name
     * @return callback provided by the plugin
     * @throws NullPointerException     if name is null
     * @throws IllegalArgumentException if plugin was not registered
     */
    JVppCallback get(final String name);

    /**
     * Sends control ping. Reply handler calls callback registered for give plugin.
     *
     * Control ping is used for initial RX thread to Java thread attachment
     * that takes place in the plugin's JNI lib
     * and to wrap dump message replies in one list.
     *
     * VPP plugins don't have to provide special control ping, therefore
     * it is necessary to providing control ping support in JVppRegistry.

     * @param clazz identifies plugin that should receive ping callback
     * @return unique identifier of message in message queue
     */
    int controlPing(final Class<? extends JVpp> clazz) throws VppInvocationException;
}
