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

package io.fd.vpp.jvpp.core.examples;

import static io.fd.vpp.jvpp.core.examples.NotificationUtils.getChangeInterfaceState;
import static io.fd.vpp.jvpp.core.examples.NotificationUtils.getDisableInterfaceNotificationsReq;
import static io.fd.vpp.jvpp.core.examples.NotificationUtils.getEnableInterfaceNotificationsReq;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;
import io.fd.vpp.jvpp.core.callback.SwInterfaceEventCallback;
import io.fd.vpp.jvpp.core.dto.SwInterfaceEvent;
import io.fd.vpp.jvpp.VppCallbackException;

public class FutureApiNotificationExample {

    private static void testFutureApi() throws Exception {
        System.out.println("Testing Java future API for notifications");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiNotificationExample");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl());
             final AutoCloseable notificationListenerReg =
                 jvppFacade.getNotificationRegistry()
                     .registerSwInterfaceEventCallback(new SwInterfaceEventCallback() {
                         public void onSwInterfaceEvent(SwInterfaceEvent reply) {
                             System.out.printf("Received interface notification: ifc: %s%n", reply);
                         }

                         public void onError (VppCallbackException ex) {
                             System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n",
                                     ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                         }
                     })) {
            System.out.println("Successfully connected to VPP");
            jvppFacade.wantInterfaceEvents(getEnableInterfaceNotificationsReq()).toCompletableFuture().get();
            System.out.println("Interface events started");

            System.out.println("Changing interface configuration");
            jvppFacade.swInterfaceSetFlags(getChangeInterfaceState()).toCompletableFuture().get();

            Thread.sleep(1000);

            jvppFacade.wantInterfaceEvents(getDisableInterfaceNotificationsReq()).toCompletableFuture().get();
            System.out.println("Interface events stopped");
            System.out.println("Disconnecting...");
        }
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
