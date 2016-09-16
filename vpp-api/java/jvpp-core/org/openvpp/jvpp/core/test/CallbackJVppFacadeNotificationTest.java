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

import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.VppCallbackException;
import org.openvpp.jvpp.core.JVppCore;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.callback.WantInterfaceEventsCallback;
import org.openvpp.jvpp.core.callfacade.CallbackJVppCoreFacade;
import org.openvpp.jvpp.core.dto.WantInterfaceEventsReply;

public class CallbackJVppFacadeNotificationTest {

    private static void testCallbackFacade() throws Exception {
        System.out.println("Testing CallbackJVppFacade for notifications");

        final JVppRegistry registry = new JVppRegistryImpl("CallbackFacadeTest");
        final JVppCore jvpp = new JVppCoreImpl();

        CallbackJVppCoreFacade jvppCallbackFacade = new CallbackJVppCoreFacade(registry, jvpp);
        System.out.println("Successfully connected to VPP");

        final AutoCloseable notificationListenerReg =
                jvppCallbackFacade.getNotificationRegistry().registerSwInterfaceSetFlagsNotificationCallback(
                        NotificationUtils::printNotification
                );

        jvppCallbackFacade.wantInterfaceEvents(NotificationUtils.getEnableInterfaceNotificationsReq(),
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
        NotificationUtils.getChangeInterfaceState().send(jvpp);

        Thread.sleep(1000);

        jvppCallbackFacade.wantInterfaceEvents(NotificationUtils.getDisableInterfaceNotificationsReq(),
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

        notificationListenerReg.close();

        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        registry.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackFacade();
    }
}
