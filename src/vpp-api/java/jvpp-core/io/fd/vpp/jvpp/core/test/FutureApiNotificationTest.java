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

package io.fd.vpp.jvpp.core.test;

import static io.fd.vpp.jvpp.core.test.NotificationUtils.getChangeInterfaceState;
import static io.fd.vpp.jvpp.core.test.NotificationUtils.getDisableInterfaceNotificationsReq;
import static io.fd.vpp.jvpp.core.test.NotificationUtils.getEnableInterfaceNotificationsReq;

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.future.FutureJVppCoreFacade;

public class FutureApiNotificationTest {

    private static void testFutureApi() throws Exception {
        System.out.println("Testing Java future API for notifications");
        try (final JVppRegistry registry = new JVppRegistryImpl("FutureApiNotificationTest");
             final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, new JVppCoreImpl());
             final AutoCloseable notificationListenerReg =
                 jvppFacade.getNotificationRegistry()
                     .registerSwInterfaceSetFlagsNotificationCallback(NotificationUtils::printNotification)) {
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
