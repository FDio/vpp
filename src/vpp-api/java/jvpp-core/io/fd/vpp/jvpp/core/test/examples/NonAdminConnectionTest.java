/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

package io.fd.vpp.jvpp.core.test.examples;

import io.fd.vpp.jvpp.*;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.callback.SwIfL2Tpv3TunnelCallback;
import io.fd.vpp.jvpp.core.dto.SwIfL2Tpv3TunnelDetails;
import io.fd.vpp.jvpp.core.dto.SwIfL2Tpv3TunnelDump;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;
import io.fd.vpp.jvpp.dto.ControlPing;

import java.io.IOException;

public class NonAdminConnectionTest {

    public static void main(String[] args) throws Exception {
        checkConnection(args);
    }

    private static void checkConnection(String[] args) throws Exception {
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackApiTest", args[0]))
        {
            int ping = registry.controlPing(JVppCoreImpl.class);
            System.out.println("Control ping - "+ping);
        }
    }

    private static void testCallbackApi(String[] args) throws Exception {
        System.out.println("Testing Java callback API with JVppRegistry");
        // uses custom shared memory prefix, to not need sudo permission
        System.out.printf("Shared memory prefix %s\n", args[0]);
        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackApiTest", args[0]);
             final JVpp jvpp = new JVppCoreImpl()) {
            registry.register(jvpp, new SwIfL2Tpv3TunnelCallback() {
                @Override
                public void onSwIfL2Tpv3TunnelDetails(SwIfL2Tpv3TunnelDetails swIfL2Tpv3TunnelDetails) {

                }

                @Override
                public void onError(VppCallbackException ex) {

                }
            });
            jvpp.send(new SwIfL2Tpv3TunnelDump());
            jvpp.controlPing(new ControlPing());

            FutureJVppCoreFacade facade = new FutureJVppCoreFacade(registry,jvpp);

            int ping = registry.controlPing(JVppCoreImpl.class);
            System.out.println("Control ping - "+ping);
            System.out.println("Connected");
            //Thread.sleep(1000);
            System.out.println("Disconnecting...");
        }
        //Thread.sleep(1000);
    }
}
