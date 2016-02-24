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

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import org.openvpp.vppjapi.vppApi;
import org.openvpp.vppjapi.vppApiCallbacks;

public class demo {

    private static volatile long stopTime;
    private static volatile long total;

    private static final BlockingQueue<Task> sharedQueue = new LinkedBlockingQueue<>(100);
    private static final Task QUIT = new Task() {
        @Override
        public void run(final vppApi api) {

        }
    };

    interface Task {

        void run(final org.openvpp.vppjapi.vppApi api);
    }

    static class Producer implements Runnable {

        private volatile long startTime;
        private final boolean debug;

        Producer(final boolean debug) {
            this.debug = debug;
        }

        @Override
        public void run() {
            for (int i = 0; i < total; i++) {
                if(i == 0) {
                    startTime = System.currentTimeMillis();
                    System.err.println("Calls start");
                }

                try {
                    sharedQueue.put(new Task() {
                        @Override
                        public void run(final vppApi api) {
                            final int requestId = api.getNodeIndex("1".getBytes());
                            if (debug && (requestId % 100 == 0)) {
                                System.err.println("Call " + requestId);
                            }
                        }
                    });
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            long elapsedTime = System.currentTimeMillis() - startTime;
            System.err.println("Requests per second (SEND) : " + total / (elapsedTime / 1000.0));

            System.err.println("Calls end");
            try {
                sharedQueue.put(QUIT);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        public void onReponse(final long contextId) {
            if (debug && (contextId % 100 == 0)) {
                System.err.println("Current response " + contextId);
                System.err.println("Current response arguments " + contextId);
            }


            if (contextId == total) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                System.err.println("Requests per second : " + total / (elapsedTime / 1000.0));
            }
        }
    }

    static class Consumer implements Runnable, vppApiCallbacks {

        private final Producer prod;
        private volatile org.openvpp.vppjapi.vppApi api;

        // Semaphore to wait for callback before executing next task
        // If we hammer requests into VPP, it slows down considerably
        // It's enough to increase maxAvailable to 2 to slow execution down by a couple orders
        private final Semaphore semaphore;

        public void setApi(final vppApi api) {
            this.api = api;
        }

        Consumer(final Producer prod, final int maxAvailable) {
            this.prod = prod;
            semaphore = new Semaphore(maxAvailable, true);
        }

        @Override
        public void run() {
            Task next;
            try {
                while((next = sharedQueue.take()) != QUIT) {
                    semaphore.acquire();
                    next.run(api);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void getNodeIndexReply(final long contextId, final long retVal, final long nodeIndex) {
            prod.onReponse(contextId);
            semaphore.release();
        }
    }


    public static void main(String[] args) throws Exception {
        total = Long.parseLong(args[0]);
        final int maxAvailable = Integer.parseInt(args[1]);
        final boolean debug = Boolean.parseBoolean(args[2]);

        final Producer prod = new Producer(debug);
        final Thread thread = new Thread(prod);
        final Consumer cons = new Consumer(prod, maxAvailable);
        final Thread thread1 = new Thread(cons);

        final vppApi test = new vppApi("test", cons);
        System.out.println("Connected OK...");
        cons.setApi(test);

        thread1.start();
        thread.start();

        thread.join();
        thread1.join();

        System.err.println("Quitting");

        test.close();
        System.exit(0);
    }

}
