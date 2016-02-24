/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

import java.util.concurrent.atomic.AtomicLong;
import org.openvpp.vppjapi.*;

public class demo {

    private static final AtomicLong counter = new AtomicLong();
    private static volatile long stopTime;
    private static volatile long startTime;
    private static volatile long total;

    public static void main (String[] args) throws Exception {
        total = Long.parseLong(args[0]);

        org.openvpp.vppjapi.vppApi api = new org.openvpp.vppjapi.vppApi ("JavaTest", new vppApiCallbacks() {

            @Override
            public void getNodeIndexReply(final long contextId, final long retVal, final long nodeIndex) {
                if(counter.get() % 100 == 0) {
                    System.err.println("Current response " + counter.get());
                    System.err.println("Current response arguments " + contextId + " " + retVal + " " + nodeIndex);
                }
                if(counter.incrementAndGet() == total) {
                    long elapsedTime = System.currentTimeMillis() - startTime;
                    System.err.println("Requests per second : " + total / (elapsedTime / 1000.0));
                    synchronized (demo.class) {
                        System.err.println("Notifying");
                        demo.class.notify();
                    }
                }
            }
        });
        System.out.println("Connected OK...");
        final long warmup = total / 4;
        System.err.println("Starting warm-up of " + warmup);
        hammer(api, warmup);
        counter.set(0);
        System.err.println("Warm-up end");
        Thread.sleep(5000);

        System.err.println("Starting calls " + total);
        startTime = System.currentTimeMillis();
        final long startSendTime = System.currentTimeMillis();
        hammer(api, total);
        final long elapsedTime = System.currentTimeMillis() - startSendTime;

        System.err.println("Calls end");

        synchronized (demo.class) {
            System.err.println("Sleeping");
            demo.class.wait();
        }

        System.err.println("Requests per second (SEND) : " + total / (elapsedTime / 1000.0));
        System.err.println("Quitting");
        System.exit(0);
    }

    private static void hammer(final org.openvpp.vppjapi.vppApi api, final long i1) throws InterruptedException {
        for (int i = 0; i < i1; i++) {
            final int requestId = api.getNodeIndex("1".getBytes());
            if(i % 100 == 0) {
                System.err.printf("%d. Call with id %d\n", i, requestId);
//                Thread.sleep(1000);
            }
        }
    }
}
