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

import java.net.InetAddress;
import org.openvpp.vppjapi.*;

public class vppApi {

    native int controlPing();
    native void test (byte[] array, byte[] array2);

    public static void main (String[] args) throws Exception {
        vppConn api = new vppConn ();
        String ipv6 = "db01::feed";
        String ipv4 = "192.168.1.1";
        InetAddress addr6 = InetAddress.getByName(ipv6);
        InetAddress addr4 = InetAddress.getByName(ipv4);
        byte[] ip4bytes = addr4.getAddress();
        byte[] ip6bytes = addr6.getAddress();
        int rv;

        api.test(ip4bytes,ip6bytes);

        rv = api.clientConnect ("JavaTest");
        if (rv == 0)
            System.out.printf ("Connected OK...");
        else
        {
            System.out.printf ("clientConnect returned %d\n", rv);
            System.exit (1);
        }
        rv = api.controlPing();
        System.out.printf ("data plane pid is %d\n", rv);

        Thread.sleep (5000);

        api.clientDisconnect();
        System.out.printf ("Done...\n");
    }
}
