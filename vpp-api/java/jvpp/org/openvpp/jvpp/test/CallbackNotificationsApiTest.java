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

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.SwInterfaceCallback;
import org.openvpp.jvpp.callback.SwInterfaceSetFlagsNotificationCallback;
import org.openvpp.jvpp.callback.WantInterfaceEventsCallback;
import org.openvpp.jvpp.callback.WantStatsCallback;
import org.openvpp.jvpp.dto.SwInterfaceDetails;
import org.openvpp.jvpp.dto.SwInterfaceSetFlags;
import org.openvpp.jvpp.dto.SwInterfaceSetFlagsNotification;
import org.openvpp.jvpp.dto.WantInterfaceEvents;
import org.openvpp.jvpp.dto.WantInterfaceEventsReply;
import org.openvpp.jvpp.dto.WantStatsReply;

public class CallbackNotificationsApiTest {

    private static class TestCallback implements SwInterfaceCallback, SwInterfaceSetFlagsNotificationCallback,
        WantStatsCallback, WantInterfaceEventsCallback {

        @Override
        public void onSwInterfaceDetails(final SwInterfaceDetails msg) {
            System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, " +
                    "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                    new String(msg.interfaceName), msg.l2AddressLength, msg.adminUpDown,
                    msg.linkUpDown, msg.linkSpeed, (int)msg.linkMtu);
        }

        @Override
        public void onSwInterfaceSetFlagsNotification(
            final SwInterfaceSetFlagsNotification msg) {

            System.out.printf("RECEIVED NOTIFICATION: ifc: %d, admin: %d, link: %d, deleted: %d\n",
                msg.swIfIndex, msg.adminUpDown, msg.linkUpDown, msg.deleted);
        }

        @Override
        public void onWantInterfaceEventsReply(final WantInterfaceEventsReply wantInterfaceEventsReply) {
            System.out.println("Interface notifications triggered successfully");
        }

        @Override
        public void onWantStatsReply(final WantStatsReply wantStatsReply) {
            System.out.println("Stats notifications triggered successfully");
        }
    }

    private static void testCallbackApi() throws Exception {
        System.out.println("Testing Java callback API for notifications");
        JVpp jvpp = new JVppImpl( new VppJNIConnection("CallbackApiTest"));
        jvpp.connect( new TestCallback());
        System.out.println("Successfully connected to VPP");

        WantInterfaceEvents wantInterfaceEvents = new WantInterfaceEvents();
        wantInterfaceEvents.pid = 1;
        wantInterfaceEvents.enableDisable = 1;
        wantInterfaceEvents.send(jvpp);
        System.out.println("Interface events started");

        // TODO test ifc dump which also triggers interface flags send

        final SwInterfaceSetFlags swInterfaceSetFlags = new SwInterfaceSetFlags();
        swInterfaceSetFlags.swIfIndex = 0;
        swInterfaceSetFlags.adminUpDown = 1;
        swInterfaceSetFlags.deleted = 0;
        swInterfaceSetFlags.send(jvpp);

        // Notification is received
        Thread.sleep(500);

        wantInterfaceEvents = new WantInterfaceEvents();
        wantInterfaceEvents.pid = 1;
        wantInterfaceEvents.enableDisable = 0;
        wantInterfaceEvents.send(jvpp);
        System.out.println("Interface events stopped");

        // TODO test 

        Thread.sleep(5000);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }
//
//    private static int getPid() {
//        try {
//            java.lang.management.RuntimeMXBean runtime =
//                java.lang.management.ManagementFactory.getRuntimeMXBean();
//            java.lang.reflect.Field jvm = runtime.getClass().getDeclaredField("jvm");
//            jvm.setAccessible(true);
//            sun.management.VMManagement mgmt =
//                (sun.management.VMManagement) jvm.get(runtime);
//            java.lang.reflect.Method pid_method =
//                mgmt.getClass().getDeclaredMethod("getProcessId");
//            pid_method.setAccessible(true);
//
//            return (Integer) pid_method.invoke(mgmt);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }

    public static void main(String[] args) throws Exception {
        testCallbackApi();
    }
}
