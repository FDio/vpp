package org.openvpp.jvpp.test;

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.callback.ControlPingCallback;
import org.openvpp.jvpp.dto.ControlPing;
import org.openvpp.jvpp.dto.ControlPingReply;

public class ControlPingTest {

    private static void testControlPing() throws Exception {
        System.out.println("Testing ControlPing using Java callback API");

        JVpp jvpp = new JVppImpl(new VppJNIConnection("ControlPingTest", new ControlPingCallback() {
            @Override
            public void onControlPingReply(final ControlPingReply reply) {
                System.out.printf("Received ControlPingReply: context=%d, retval=%d, clientIndex=%d vpePid=%d\n",
                        reply.context, reply.retval, reply.clientIndex, reply.vpePid);
            }
        }));
        System.out.println("Successfully connected to VPP");
        Thread.sleep(1000);

        jvpp.send(new ControlPing());

        Thread.sleep(2000);

        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testControlPing();
    }
}
