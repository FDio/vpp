#!/usr/bin/env python
from __future__ import print_function
import unittest
import test_base
import vpp_papi
import pot, snat
print('Plugins:')
vpp_papi.plugin_show()
r = vpp_papi.connect('ole')

r = vpp_papi.show_version()
print('R:', r)

r = snat.snat_interface_add_del_feature(1, 1, 1)
print('R:', r)

vpp_papi.disconnect()
