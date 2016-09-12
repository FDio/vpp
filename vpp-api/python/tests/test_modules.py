from __future__ import print_function
import unittest
import vpp_papi
import pot, snat
print('Plugins:')
vpp_papi.plugin_show()
r = vpp_papi.connect('ole')

r = vpp_papi.show_version()
print('R:', r)

r = snat.snat_interface_add_del_feature(1, 1, 1)
print('R:', r)

list_name = 'foobar'
r = pot.pot_profile_add(0, 1, 123, 123, 0, 12, 0, 23, len(list_name), list_name)
print('R:', r)
vpp_papi.disconnect()
