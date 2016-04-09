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

import org.openvpp.vppjapi.*;

public class demo {
    public static void main (String[] args) throws Exception {
        vppApi api = new vppApi ("JavaTest");
        System.out.printf ("Connected OK...");

        String intlist;
        int [] contexts;
        int i, limit;
        int trips;
        int rv, errors, saved_error;
        long before, after;

        if (false)
        {
            intlist = api.getInterfaceList ("");
            System.out.printf ("Unfiltered interface list:\n%s", intlist);
            
            trips = 0;
            
            contexts = new int[6];
            
            for (i = 0; i < 6; i++)
            {
                contexts[i] = api.swInterfaceSetFlags 
                    (5 + i /* sw_if_index */,
                     (byte)1 /* admin_up */,
                     (byte)1 /* link_up (ignored) */,
                     (byte)0 /* deleted */);
            }
            
            /* Thread.sleep (1); */
            errors = 0;
            saved_error = 0;
            
            for (i = 0; i < 6; i ++)
            {
                while (true)
                {
                    rv = api.getRetval (contexts[i], 1 /* release */);
                    if (rv != -77)
                        break;
                    Thread.sleep (1);
                    trips++;
                }
                if (rv < 0)
                {
                    saved_error = rv;
                    errors++;
                }
            }
            
            if (errors == 0)
                System.out.printf ("intfcs up...\n");
            else
                System.out.printf 
                    ("%d errors, last error %d...\n", errors, saved_error);
        }
        
        limit = 250000;
        saved_error = 0;
        errors = 0;
        contexts = new int [limit];
        byte [] address = new byte [4];
        byte [] zeros = new byte [4];

        address[0] = (byte)192;
        address[1] = (byte)168;
        address[2] = (byte)2;
        address[3] = (byte)1;

        for (i = 0; i < 4; i++)
            zeros[i] = 0;

        System.out.printf ("start %d route ops ...", limit);

        before = System.currentTimeMillis();

        for (i = 0; i < limit; i++) {
            contexts[i] = api.ipAddDelRoute 
                (0 /* int nextHopSwIfIndex */, 
                 0 /* int vrfId */, 
                 0 /* int lookupInVrf */, 
                 0 /* int resolveAttempts */, 
                 0 /* int classifyTableIndex */, 
                 (byte)0 /* byte createVrfIfNeeded */, 
                 (byte)0 /* byte resolveIfNeeded */, 
                 (byte)1 /* byte isAdd */, 
                 (byte)1 /* byte isDrop */, 
                 (byte)0 /* byte isIpv6 */, 
                 (byte)0 /* byte isLocal */, 
                 (byte)0 /* byte isClassify */, 
                 (byte)0 /* byte isMultipath */, 
                 (byte)0 /* byte notLast */, 
                 (byte)0 /* byte nextHopWeight */, 
                 (byte)32 /* byte dstAddressLength */, 
                 address, 
                 zeros);
            
            address[3] += 1;
            if (address[3] == 0)
            {
                address[2] += 1;
                if (address[2] == 0)
                {
                    address[1] += 1;
                    {
                        if (address[1] == 0)
                        {
                            address[0] += 1;
                        }
                    }
                }
            }
        }

        trips = 0;
                        
        for (i = 0; i < limit; i++)
        {
            while (true)
            {
                rv = api.getRetval (contexts[i], 1 /* release */);
                if (rv != -77)
                    break;
                Thread.sleep (1);
                trips++;
            }
            if (rv < 0)
            {
                saved_error = rv;
                errors++;
            }
        }

        after = System.currentTimeMillis();


        if (errors == 0)
            System.out.printf ("done %d route ops (all OK)...\n", limit);
        else
            System.out.printf 
                ("%d errors, last error %d...\n", errors, saved_error);
        
        System.out.printf ("result in %d trips\n", trips);

        System.out.printf ("%d routes in %d milliseconds, %d routes/msec\n",
                           limit, after - before, 
                           limit / (after - before));

        api.close();
        System.out.printf ("Done...\n");
    }
}
