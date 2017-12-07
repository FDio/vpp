#!/usr/bin/env python

from __future__ import print_function

import os
import fnmatch
import inspect
import time

from vpp_papi import VPP 

vpp_json_dir = '/usr/share/vpp/api/'

jsonfiles = []

for root, dirnames, filenames in os.walk(vpp_json_dir):
    for filename in fnmatch.filter(filenames, '*.api.json'):
        jsonfiles.append(os.path.join(vpp_json_dir, filename))

if not jsonfiles:
    print('Error: no json api files found')
    exit(-1)

vpp = VPP(jsonfiles)
r = vpp.connect("test_papi")
print(r)

for intf in vpp.sw_interface_dump():
    print(intf.interface_name.decode())

def papi_event_handler(name, event):
    # if event.vl_msg_id == vpp_papi.VL_API_VNET_INTERFACE_COUNTERS:
    #     format = '>' + str(int(len(event.data) / 8)) + 'Q'
    #     counters = struct.unpack(format, event.data)
    #     print('Counters:', counters)
    #     return

    print("New event: %s: %s" % (name, event))
    # print('Unknown message id:', event.vl_msg_id)



vpp.register_event_callback(papi_event_handler)
r = vpp.sw_interface_event(sw_if_index=0, admin_up_down=1)
print("sw_interface_event reply: %s" % r)
#
# Wait for some stats
#
#time.sleep(60)
#r = vpp.want_stats(False, pid)
# r = vpp.disconnect()

exit(vpp.disconnect())
