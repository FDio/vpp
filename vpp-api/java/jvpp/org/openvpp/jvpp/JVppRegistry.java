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

import org.openvpp.jvpp.callback.JVppCallback;

/**
 * The registry that stores callbacks.
 */
public interface JVppRegistry extends AutoCloseable {
    /**
     * Registers callback for the given plugin.
     *
     * @param name     plugin name
     * @param callback callback provided by the plugin
     * @throws NullPointerException     if name or callback is null
     * @throws IllegalArgumentException if plugin was already registered
     */
    void register(JVpp jvpp, JVppCallback callback);

    /**
     * Unregisters callback for the given plugin.
     *
     * @param name plugin name
     * @throws NullPointerException     if name is null
     * @throws IllegalArgumentException if plugin was not registered
     */
    void unregister(String name);

    /**
     * Returns callback registered for the plugin.
     *
     * @param name plugin name
     * @return callback provided by the plugin
     * @throws NullPointerException     if name is null
     * @throws IllegalArgumentException if plugin was not registered
     */
    JVppCallback get(String name);
}
