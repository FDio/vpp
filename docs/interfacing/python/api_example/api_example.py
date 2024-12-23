#!/usr/bin/env python3

import fnmatch
import os
import time
from vpp_papi import VPPApiClient, VppEnum

'''
This example will show api three based use case
1. request/reply
    api: show_version
2. dump/details
    api: sw_interface_dump
3. event/event_cb
    api: want_interface_events

'''


# Create VPP client object
# Load the API definitions from VPP using the API itself
vpp = VPPApiClient(bootstrapapi=True)

# Connect to VPP, specifying a client name
r = vpp.connect('ping-test')
assert(r == 0)

# Show VPP version
rv = vpp.api.show_version()
print(rv)
print(f'VPP version:\n  {rv.version}\n  {rv.build_date}\n  {rv.build_directory}')

# Display VPP interfaces
print('VPP interfaces:')
interfaces = vpp.api.sw_interface_dump()
for intf in interfaces:
    print(f'  {intf.interface_name}')

# Define event callback handler
def papi_event_handler(msgname, result):
    print(f'{msgname}:\n   {result}')

# Register event callback function
r = vpp.register_event_callback(papi_event_handler)

# Send subscription request for interface events
r = vpp.api.want_interface_events(enable_disable=True, pid=os.getpid())

# Generate an interface event by flapping the first interface
if len(interfaces) > 0:
    upflag = VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
    sw_if_index = interfaces[0].sw_if_index
    r = vpp.api.sw_interface_set_flags(sw_if_index=sw_if_index, flags=0)
    r = vpp.api.sw_interface_set_flags(sw_if_index=sw_if_index, flags=upflag)

# Sleep to allow VPP interface status updates
time.sleep(1)  # Keep the script running to receive events

# Unsubscribe from interface events
r = vpp.api.want_interface_events(enable_disable=False, pid=os.getpid())

# Disconnect from VPP
print('Disconnecting from VPP')
r = vpp.disconnect()

exit(r)
