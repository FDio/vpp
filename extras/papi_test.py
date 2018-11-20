#!/usr/bin/env python

from __future__ import print_function

import os
import fnmatch

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
if r != 0:
    print('VPP connection failed')
else:
    print('VPP connection successful')

for intf in vpp.api.sw_interface_dump():
    print(intf.interface_name.decode() + ", link speed:" + str(intf.link_speed))

exit(vpp.disconnect())
