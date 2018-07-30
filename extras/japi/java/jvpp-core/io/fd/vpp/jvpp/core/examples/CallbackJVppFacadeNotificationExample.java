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

import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.core.JVppCore;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.callback.WantInterfaceEventsReplyCallback;
import io.fd.vpp.jvpp.core.callback.SwInterfaceEventCallback;
import io.fd.vpp.jvpp.core.callfacade.CallbackJVppCoreFacade;
import io.fd.vpp.jvpp.core.dto.WantInterfaceEventsReply;
import io.fd.vpp.jvpp.core.dto.SwInterfaceEvent;

public class CallbackJVppFacadeNotificationExample {

    private static void testCallbackFacade() throws Exception {
        System.out.println("Testing CallbackJVppFacade for notifications");

        try (final JVppRegistry registry = new JVppRegistryImpl("CallbackFacadeExample");
             final JVppCore jvpp = new JVppCoreImpl()) {
            final CallbackJVppCoreFacade jvppCallbackFacade = new CallbackJVppCoreFacade(registry, jvpp);
            System.out.println("Successfully connected to VPP");

            final AutoCloseable notificationListenerReg =
                jvppCallbackFacade.getEventRegistry().registerSwInterfaceEventCallback(
                        new SwInterfaceEventCallback() {
                            public void onSwInterfaceEvent(SwInterfaceEvent reply) {
                                System.out.printf("Received interface notification: ifc: %s%n", reply);
                            }

                            public void onError (VppCallbackException ex) {
                                System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n",
                                        ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                            }
                        });

            jvppCallbackFacade.wantInterfaceEvents(NotificationUtils.getEnableInterfaceNotificationsReq(),
                new WantInterfaceEventsReplyCallback() {
                    @Override
                    public void onWantInterfaceEventsReply(final WantInterfaceEventsReply reply) {
                        System.out.println("Interface events started");
                    }

                    @Override
                    public void onError(final VppCallbackException ex) {
                        System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n",
                            ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                    }
                });

            System.out.println("Changing interface configuration");
            NotificationUtils.getChangeInterfaceState().send(jvpp);

            Thread.sleep(1000);

            jvppCallbackFacade.wantInterfaceEvents(NotificationUtils.getDisableInterfaceNotificationsReq(),
                new WantInterfaceEventsReplyCallback() {
                    @Override
                    public void onWantInterfaceEventsReply(final WantInterfaceEventsReply reply) {
                        System.out.println("Interface events stopped");
                    }

                    @Override
                    public void onError(final VppCallbackException ex) {
                        System.out.printf("Received onError exception: call=%s, context=%d, retval=%d%n",
                            ex.getMethodName(), ex.getCtxId(), ex.getErrorCode());
                    }
                });

            notificationListenerReg.close();

            Thread.sleep(2000);
            System.out.println("Disconnecting...");
        }
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testCallbackFacade();
    }
}
