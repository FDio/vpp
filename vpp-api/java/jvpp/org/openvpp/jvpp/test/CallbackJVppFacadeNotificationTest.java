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
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.WantInterfaceEventsCallback;
import org.openvpp.jvpp.callfacade.CallbackJVppFacade;
import org.openvpp.jvpp.dto.WantInterfaceEventsReply;

/**
 * CallbackJVppFacade together with CallbackJVppFacadeCallback allow for setting different callback for each request.
 * This is more convenient than the approach shown in CallbackApiTest.
 */
public class CallbackJVppFacadeNotificationTest {

    private static void testCallbackFacade() throws Exception {
        System.out.println("Testing CallbackJVppFacade for notifications");

        JVpp jvpp = new JVppImpl(new VppJNIConnection("CallbackApiTest"));

        CallbackJVppFacade jvppCallbackFacade = new CallbackJVppFacade(jvpp);
        System.out.println("Successfully connected to VPP");

        final AutoCloseable autoCloseable =
            jvppCallbackFacade.getNotificationRegistry().registerSwInterfaceSetFlagsNotificationCallback(
                Notificationutils::printNotification
            );

        jvppCallbackFacade.wantInterfaceEvents(Notificationutils.getEnableInterfaceNotificationsReq(),
            new WantInterfaceEventsCallback() {
                @Override
                public void onWantInterfaceEventsReply(final WantInterfaceEventsReply reply) {
                    System.out.println("Interface events started");
                }

                @Override
                public void onError(final VppCallbackException ex) {
                    System.out.printf("Received onError exception: call=%s, context=%d, retval=%d\n",
                        ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                }
            });

        System.out.println("Changing interface configuration");
        Notificationutils.getChangeInterfaceState().send(jvpp);

        Thread.sleep(1000);

        jvppCallbackFacade.wantInterfaceEvents(Notificationutils.getDisableInterfaceNotificationsReq(),
            new WantInterfaceEventsCallback() {
                @Override
                public void onWantInterfaceEventsReply(final WantInterfaceEventsReply reply) {
                    System.out.println("Interface events stopped");
                }

                @Override
                public void onError(final VppCallbackException ex) {
                    System.out.printf("Received onError exception: call=%s, context=%d, retval=%d\n",
                        ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                }
            });

        autoCloseable.close();

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackFacade();
    }
}
