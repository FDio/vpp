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

import java.lang.reflect.Field;
import org.openvpp.jvpp.JVppImpl;
import org.openvpp.jvpp.VppJNIConnection;
import org.openvpp.jvpp.dto.GetNodeGraph;
import org.openvpp.jvpp.dto.GetNodeGraphReply;
import org.openvpp.jvpp.future.FutureJVppFacade;
import sun.misc.Unsafe;

/**
 * <p>Tests VPP Node graph parsing.<br> Alternative to:<br>
 *
 * <pre>{@code
 * vppctl show vlib graph
 * }
 * </pre>
 */
public class VppNodeGraphTest {

    private static final Unsafe UNSAFE;
    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            UNSAFE = (Unsafe) f.get(null);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    private static void print(GetNodeGraphReply reply) {
        final long shm = reply.replyInShmem;
        final long shm_reversed = Long.reverseBytes(shm);

        System.out.printf("GetNodeGraph: context=%d, replyInShmem=%s, replyInShmemReversed=%s\n",
            reply.context, Long.toHexString(shm), Long.toHexString(shm_reversed));

        final byte aByte = UNSAFE.getByte(shm_reversed);
        System.out.printf("GetNodeGraph: aByte=%02X\n", aByte);

    }

    private static void testNodeGraph() throws Exception {
        System.out.println("Testing VPP Node graph parsing using Java callback API");
        final JVppImpl jvpp = new JVppImpl(new VppJNIConnection("VppNodeGraphTest"));
        final FutureJVppFacade jvppFacade = new FutureJVppFacade(jvpp);

        System.out.println("Successfully connected to VPP");
        Thread.sleep(1000);

        final GetNodeGraphReply reply =
            jvppFacade.getNodeGraph(new GetNodeGraph()).toCompletableFuture().get();
        print(reply);


        System.out.println("Disconnecting...");
        jvpp.close();
        Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        testNodeGraph();
    }
}
