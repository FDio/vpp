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

package io.fd.vpp.jvpp.nat.test;

import io.fd.vpp.jvpp.AbstractCallbackApiTest;
import io.fd.vpp.jvpp.nat.JVppNatImpl;

import java.util.logging.Logger;

public class CallbackApiTest extends AbstractCallbackApiTest {

    private static Logger LOG = Logger.getLogger(CallbackApiTest.class.getName());


    public static void main(String[] args) throws Exception {
        LOG.info("Testing ControlPing using Java callback API for core plugin");
        testControlPing(args[0], new JVppNatImpl());
    }
}
