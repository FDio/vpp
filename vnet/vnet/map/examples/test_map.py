#!/usr/bin/env python

import time,argparse,sys,cmd, unittest
from ipaddress import *

parser = argparse.ArgumentParser(description='VPP MAP test')
parser.add_argument('-i', nargs='*', action="store", dest="inputdir")
args = parser.parse_args()

for dir in args.inputdir:
    sys.path.append(dir)
from vpp_papi import *

#
# 1:1 Shared IPv4 address, shared BR (16) VPP CLI
#
def lw46_shared(ip4_pfx_str, ip6_pfx_str, ip6_src_str, ea_bits_len, psid_offset, psid_len, ip6_src_ecmp = False):
    ip4_pfx = ip_network(ip4_pfx_str)
    ip6_src = ip_address(ip6_src_str)
    ip6_dst = ip_network(ip6_pfx_str)
    ip6_nul = IPv6Address(u'0::0')
    mod = ip4_pfx.num_addresses / 1024

    for i in range(ip4_pfx.num_addresses):
        a = time.clock()
        t = map_add_domain(0, ip6_nul.packed, ip4_pfx[i].packed, ip6_src.packed, 0, 32, 128, ea_bits_len, psid_offset, psid_len, 0, 0)
        #print "Return from map_add_domain", t
        if t == None:
            print "map_add_domain failed"
            continue
        if t.retval != 0:
            print "map_add_domain failed", t
            continue
        for psid in range(0x1 << int(psid_len)):
            r = map_add_del_rule(0, t.index, 1, (ip6_dst[(i * (0x1<<int(psid_len))) + psid]).packed, psid)
            #print "Return from map_add_del_rule", r

        if ip6_src_ecmp and not i % mod:
            ip6_src = ip6_src + 1

        print "Running time:", time.clock() - a

class TestMAP(unittest.TestCase):
    '''
    def test_delete_all(self):
        t = map_domain_dump(0)
        self.assertNotEqual(t, None)
        print "Number of domains configured: ", len(t)
        for d in t:
            ts = map_del_domain(0, d.domainindex)
            self.assertNotEqual(ts, None)
        t = map_domain_dump(0)
        self.assertNotEqual(t, None)
        print "Number of domains configured: ", len(t)
        self.assertEqual(len(t), 0)

    '''

    def test_a_million_rules(self):
        ip4_pfx = u'192.0.2.0/24'
        ip6_pfx = u'2001:db8::/32'
        ip6_src = u'2001:db8::1'
        psid_offset = 6
        psid_len = 6
        ea_bits_len = 0
        lw46_shared(ip4_pfx, ip6_pfx, ip6_src, ea_bits_len, psid_offset, psid_len)

#
# RX thread, that should sit on blocking vpe_api_read()

# 


#
#
#
import threading
class RXThread (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print "Starting "
        i = 0
        while True:
            msg = vpe_api_read()
            if msg:
                #print msg
                id = unpack('>H', msg[0:2])
                size = unpack('>H', msg[2:4])
                print "Received", id, "of size", size
                i += 1
                #del msg
                continue

            #time.sleep(0.001)
        return

# Create RX thread
rxthread = RXThread()
rxthread.setDaemon(True)
        
print "Connect", connect_to_vpe("client124")
import timeit
rxthread.start()
print "After thread started"

#pneum_kill_thread()
print "After thread killed"

#t = show_version(0)
#print "Result from show version", t

print timeit.timeit('t = show_version(0)', number=1000, setup="from __main__ import show_version")
time.sleep(10)
#print timeit.timeit('control_ping(0)', number=10, setup="from __main__ import control_ping")


disconnect_from_vpe()
sys.exit()


print t.program, t.version,t.builddate,t.builddirectory

'''

t = map_domain_dump(0)
if not t:
    print('show map domain failed')

for d in t:
    print("IP6 prefix:",str(IPv6Address(d.ip6prefix)))
    print( "IP4 prefix:",str(IPv4Address(d.ip4prefix)))
'''

suite = unittest.TestLoader().loadTestsFromTestCase(TestMAP)
unittest.TextTestRunner(verbosity=2).run(suite)

disconnect_from_vpe()


