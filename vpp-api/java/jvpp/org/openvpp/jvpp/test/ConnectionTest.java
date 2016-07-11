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

package org.openvpp.jvpp.test;

import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.VppJNIConnection;

/**
 * Run using:
 * sudo java -cp build-vpp-native/vpp-api/java/jvpp-registry-16.09.jar org.openvpp.jvpp.test.ConnectionTest
 */
public class ConnectionTest {

    private static void testConnect() throws Exception {
        System.out.println("Testing JNI connection with JVppRegistry");
        JVppRegistry registry = new JVppRegistryImpl();
        // TODO: move connect/disconnect to the registry
        final VppJNIConnection connection = new VppJNIConnection("CallbackApiWithRegistryTest");
        connection.connect(registry);
        System.out.println("Successfully connected to vpp");

        // FIXME add getName to interface callback (parameter for interface generation)
        // registry.register("vpp-core", new CallbackApiTest.TestCallback()); // can be invoked before or after

        Thread.sleep(5000);

        System.out.println("Disconnecting...");
        connection.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testConnect();
    }
}
