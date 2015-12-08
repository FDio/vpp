#!/usr/bin/env python

# Copyright (c) 2009-2014 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading
import time
from scapy.all import *
from Queue import *

iface = 'veth1'

class SnifferThread(threading.Thread) :
    def __init__(self,q,iface,flt,timeout) :
        threading.Thread.__init__(self)
        self.q = q
        self.iface = iface
        self.timeout = timeout
        self.flt = flt
        print("Sniffers reporting for service on ",self.iface)
 
    def run(self) :
        conf.iface=self.iface
        conf.iface6=self.iface

        r = sniff(filter=self.flt,iface=self.iface,timeout=self.timeout,prn=lambda x: x.summary())
        self.q.put(r)



# New "SR" function
#   Fire off thread with filter and expected answer packet(s).
# Fire off sniffer thread, main thread sends packet
#   Returns true if found

def sr2(answer, *args, **kwargs):
    q = Queue()
    print("Creating SnifferThreadWorkerThread")
    flt='ip proto 41'
    iface='veth1'
    sniffer = SnifferThread(q,iface,flt,1)
    sniffer.setDaemon(True)
    sniffer.start()

    print "Sending packet:"
    send(*args, **kwargs)
    sniffer.join()
    ps = q.get()
    
#    ps.summary()
    print "Number of packets sniffed:", len(ps)

    for p in ps:
        ip = p.getlayer(1)
        print "Comparing", ip.summary(), "and", answer.summary()
        if ip == answer:
            print "We have a match!!"
            return True
    return False

aip6 = IPv6(dst='2002:0a0a:0a0a::12')/ICMPv6EchoRequest()
answer= IP(src="10.0.0.100",dst="10.10.10.10",ttl=63)/aip6
packet = IPv6(dst='2002:0a0a:0a0a::12')/ICMPv6EchoRequest()

# From IPv6
sr2(answer, packet,iface='veth1')

#From IPv4
packet = IP(src='10.10.10.10',dst='10.0.0.100')/IPv6(src='2002:0a0a:0a0a::12',dst='1::2')/ICMPv6EchoRequest()
sr2(answer, packet,iface='veth1')
