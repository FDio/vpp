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

package io.fd.vpp.jvpp.ioamexport.examples;

import java.net.InetAddress;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.ioamexport.JVppIoamexportImpl;
import io.fd.vpp.jvpp.ioamexport.future.FutureJVppIoamexportFacade;
import io.fd.vpp.jvpp.ioamexport.dto.IoamExportIp6EnableDisable;
import io.fd.vpp.jvpp.ioamexport.dto.IoamExportIp6EnableDisableReply;

public class IoamExportApiExample {

    public static void main(String[] args) throws Exception {
        ioamExportTestApi();
    }

    private static void ioamExportTestApi() throws Exception {
        System.out.println("Testing Java API for ioam export plugin");
        try (final JVppRegistry registry = new JVppRegistryImpl("ioamExportApiExample");
             final JVpp jvpp = new JVppIoamexportImpl()) {
	    FutureJVppIoamexportFacade ioamexportJvpp = new FutureJVppIoamexportFacade(registry,jvpp);
            System.out.println("Sending ioam export request...");
	    IoamExportIp6EnableDisable request = new IoamExportIp6EnableDisable();
            request.isDisable = 0;
	    InetAddress collectorAddress = InetAddress.getByName("2001:0DB8:AC10:FE01:0000:0000:0000:0000");
	    InetAddress srcAddress = InetAddress.getByName("2001:0DB8:AC10:FE01:0000:0000:0000:0001");
	    request.collectorAddress = collectorAddress.getAddress();
	    request.srcAddress = srcAddress.getAddress();
	    IoamExportIp6EnableDisableReply reply = ioamexportJvpp.ioamExportIp6EnableDisable(request).toCompletableFuture().get();
            System.out.printf("IoamExportIp6EnableDisableReply = "+reply.toString()+"%n");

            Thread.sleep(1000);

            System.out.println("Disconnecting...");
        }
    }
}
