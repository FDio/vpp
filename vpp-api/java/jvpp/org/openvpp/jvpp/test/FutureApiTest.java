package org.openvpp.jvpp.test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.dto.GetNodeIndex;
import org.openvpp.jvpp.dto.GetNodeIndexReply;
import org.openvpp.jvpp.dto.JVppReply;
import org.openvpp.jvpp.dto.ShowVersion;
import org.openvpp.jvpp.dto.ShowVersionReply;
import org.openvpp.jvpp.dto.SwInterfaceDetails;
import org.openvpp.jvpp.dto.SwInterfaceDetailsReplyDump;
import org.openvpp.jvpp.dto.SwInterfaceDump;
import org.openvpp.jvpp.future.FutureJVppFacade;
import org.openvpp.jvpp.future.FutureJVppFacadeCallback;

public class FutureApiTest {

    private static void testShowVersion(final FutureJVppFacade jvpp) {
        System.out.println("Sending ShowVersion request...");
        try {
            final Future<JVppReply<ShowVersion>> replyFuture = jvpp.send(new ShowVersion());
            final ShowVersionReply reply = (ShowVersionReply) replyFuture.get(); // TODO can we get rid of that cast?
            System.out.printf("Received ShowVersionReply: context=%d, retval=%d, program=%s, " +
                            "version=%s, buildDate=%s, buildDirectory=%s\n",
                    reply.context, reply.retval, new String(reply.program), new String(reply.version),
                    new String(reply.buildDate), new String(reply.buildDirectory));
        } catch (Exception e) {
            System.err.printf("ShowVersion request failed:\n");
            e.printStackTrace();
        }
    }

    /**
     * This test will fail with some error code if node 'node0' is not defined.
     * TODO: consider adding error messages specific for given api calls
     */
    private static void testGetNodeIndex(final FutureJVppFacade jvpp) {
        System.out.println("Sending GetNodeIndex request...");
        try {
            final GetNodeIndex request = new GetNodeIndex();
            request.nodeName = "node0".getBytes();
            final Future<JVppReply<GetNodeIndex>> replyFuture = jvpp.send(request);
            final GetNodeIndexReply reply = (GetNodeIndexReply) replyFuture.get();
            System.out.printf("Received GetNodeIndexReply: context=%d, retval=%d, nodeIndex=%d\n",
                    reply.context, reply.retval, reply.nodeIndex);
        } catch (Exception e) {
            System.err.printf("GetNodeIndex request failed:\n");
            e.printStackTrace();
        }
    }

    private static void testSwInterfaceDump(final FutureJVppFacade jvpp) {
        System.out.println("Sending SwInterfaceDump request...");
        try {
            final SwInterfaceDump request = new SwInterfaceDump();
            request.nameFilterValid = 0;
            request.nameFilter = "".getBytes();
            final Future<JVppReply<SwInterfaceDump>> replyFuture = jvpp.send(request);
            final SwInterfaceDetailsReplyDump reply = (SwInterfaceDetailsReplyDump) replyFuture.get();

            if (reply == null) {
                throw new IllegalStateException("SwInterfaceDetailsReplyDump is null!");
            }
            if (reply.swInterfaceDetails == null) {
                throw new IllegalStateException("SwInterfaceDetailsReplyDump.swInterfaceDetails is null!");
            }

            for (SwInterfaceDetails details : reply.swInterfaceDetails) {
                if (details == null) {
                    throw new IllegalStateException("reply.swInterfaceDetails contains null element!");
                }

                System.out.printf("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, " +
                                "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                        new String(details.interfaceName), details.l2AddressLength, details.adminUpDown,
                        details.linkUpDown, details.linkSpeed, (int) details.linkMtu);
            }
        } catch (Exception e) {
            System.err.printf("SwInterfaceDump request failed:\n");
            e.printStackTrace();
        }
    }

    private static void testFutureApi() throws Exception {
        System.out.println("Testing Java future API");

        final Map<Integer, CompletableFuture<? extends JVppReply<?>>>  map = new HashMap<>();
        final org.openvpp.jvpp.JVppImpl impl =
                new org.openvpp.jvpp.JVppImpl(new VppJNIConnection("FutureApiTest", new FutureJVppFacadeCallback(map)));
        final FutureJVppFacade jvpp = new FutureJVppFacade(impl, map);
        System.out.println("Successfully connected to VPP");

        testShowVersion(jvpp);
        testGetNodeIndex(jvpp);
        testSwInterfaceDump(jvpp);

        System.out.println("Disconnecting...");
        // TODO we should consider adding jvpp.close(); to the facade
        impl.close();
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}
