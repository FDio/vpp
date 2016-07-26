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

package org.openvpp.jvpp.core.test;

import static org.openvpp.jvpp.core.test.NotificationUtils.getChangeInterfaceState;
import static org.openvpp.jvpp.core.test.NotificationUtils.getDisableInterfaceNotificationsReq;
import static org.openvpp.jvpp.core.test.NotificationUtils.getEnableInterfaceNotificationsReq;
import static org.openvpp.jvpp.core.test.NotificationUtils.printNotification;

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.callback.SwInterfaceSetFlagsCallback;
import org.openvpp.jvpp.core.callback.SwInterfaceSetFlagsNotificationCallback;
import org.openvpp.jvpp.core.callback.WantInterfaceEventsCallback;
import org.openvpp.jvpp.core.dto.SwInterfaceSetFlagsNotification;
import org.openvpp.jvpp.core.dto.SwInterfaceSetFlagsReply;
import org.openvpp.jvpp.core.dto.WantInterfaceEventsReply;

public class CallbackNotificationApiTest {

    private static class TestCallback implements SwInterfaceSetFlagsNotificationCallback,
        WantInterfaceEventsCallback, SwInterfaceSetFlagsCallback {

        @Override
        public void onSwInterfaceSetFlagsNotification(
            final SwInterfaceSetFlagsNotification msg) {
            printNotification(msg);
        }

        @Override
        public void onWantInterfaceEventsReply(final WantInterfaceEventsReply wantInterfaceEventsReply) {
            System.out.println("Interface notification stream updated");
        }

        @Override
        public void onSwInterfaceSetFlagsReply(final SwInterfaceSetFlagsReply swInterfaceSetFlagsReply) {
            System.out.println("Interface flags set successfully");
        }

        @Override
        public void onError(VppCallbackException ex) {
            System.out.printf("Received onError exception in getNodeIndexCallback: call=%s, reply=%d, context=%d\n",
                ex.getMethodName(), ex.getErrorCode(), ex.getCtxId());

        }
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API for notifications");
        JVppRegistry registry = new JVppRegistryImpl("CallbackNotificationTest");
        JVpp jvpp = new JVppCoreImpl();

        registry.register(jvpp, new TestCallback());
        System.out.println("Successfully connected to VPP");

        getEnableInterfaceNotificationsReq().send(jvpp);
        System.out.println("Interface notifications started");
        // TODO test ifc dump which also triggers interface flags send

        System.out.println("Changing interface configuration");
        getChangeInterfaceState().send(jvpp);

        // Notifications are received
        Thread.sleep(500);

        getDisableInterfaceNotificationsReq().send(jvpp);
        System.out.println("Interface events stopped");

        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        registry.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }
}
