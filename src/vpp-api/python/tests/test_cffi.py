#!/usr/bin/env python

from __future__ import print_function
import unittest, sys, threading, struct, logging, os, time
from vpp_papi import VPP
from ipaddress import *
import glob, json
import binascii
papi_event = threading.Event()
import glob

import fnmatch
import os

jsonfiles = []
for root, dirnames, filenames in os.walk('../../../build-root/'):
    if root.find('install-') == -1: continue
    for filename in fnmatch.filter(filenames, '*.api.json'):
        jsonfiles.append(os.path.join(root, filename))


def handler(name, msg):
    print('Received reply', name)
    time.sleep(1)

def thread_msg_handler(vpp, test, messagecount):
    count = 0
    while True:
        msg = vpp.message_queue.get()
        test.assertEqual(msg.retval, 0)
        vpp.message_queue.task_done()
        count += 1
        if count >= messagecount:
            print('Received all messages', count)
            return

class TestMissing(unittest.TestCase):
    def test_request_reply_function(self):
        vpp = VPP(jsonfiles)

        vpp.connect('test_missing', mode=vpp.VPP_MODE_SYNC)


        mac1 = binascii.unhexlify("fa:16:3e:dc:57:4e".replace(':',''))
        mac1_mask = binascii.unhexlify("ff:ff:ff:ff:ff:ff".replace(':',''))

        # Create a macip acl
        rules =[{'is_permit':1,
                 'is_ipv6': 0,
                 'src_mac': mac1,
                 'src_mac_mask': mac1_mask,
                 'src_ip_addr': ip_address(unicode("10.1.1.1")).packed,
                 'src_ip_prefix_len': 32 }]
        t = vpp.macip_acl_add(r=rules, count=len(rules))
        print('ACL add', t)
        # Dump all mac_ip acls on all interfaces indexed by interface ID
        t = vpp.macip_acl_interface_get()
        print('T', t)


        vpp.disconnect()

    def test_slow_msg_handler(self):
        messagecount = 100000
        vpp = VPP(jsonfiles)
        t = threading.Thread(target=thread_msg_handler,
                             args=(vpp, self, messagecount))
        t.start()

        vpp.connect('test_missing', mode=vpp.VPP_MODE_ASYNC)


        for i in range(messagecount):
            vpp.show_version()

        print('Waiting for all replies', vpp.message_queue.qsize())
        t.join()
        print('Done waiting for all replies')
        vpp.disconnect()

if __name__ == '__main__':
    unittest.main()
