#!/usr/bin/env python3

from __future__ import print_function
from vpp_papi import VPPApiClient
import fnmatch
import os
import time

"""
This example will show api three based use case
1. request/reply
    api: show_version
2. dump/details
    api: sw_interface_dump
3. event/event_cb
    api: want_interface_events

"""

parser = argparse.ArgumentParser(description="VPP API Client Script")

parser.add_argument(
    "--core-json-dir",
    type=str,
    default="/opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core",
    help="Path to VPP core JSON directory (default: /opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core)",
)
parser.add_argument(
    "--plugins-json-dir",
    type=str,
    default="/opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/plugins",
    help="Path to VPP plugins JSON directory (default: /opt/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/plugins)",
)

args = parser.parse_args()

# Core and plugins JSON directories
vpp_core_json_dir = args.core_json_dir
vpp_plugins_json_dir = args.plugins_json_dir

jsonfiles = []

# Collecting API JSON files from core directory
for root, dirnames, filenames in os.walk(vpp_core_json_dir):
    for filename in fnmatch.filter(filenames, "*.api.json"):
        jsonfiles.append(os.path.join(root, filename))  # Fixed to use root

# Collecting API JSON files from plugins directory
for root, dirnames, filenames in os.walk(vpp_plugins_json_dir):
    for filename in fnmatch.filter(filenames, "*.api.json"):
        jsonfiles.append(os.path.join(root, filename))  # Fixed to use root

# Check if any JSON files were found
if not jsonfiles:
    print("Error: no JSON API files found")
    exit(-1)

# Create VPP client object
vpp = VPPApiClient(apidir=[vpp_core_json_dir, vpp_plugins_json_dir], apifiles=jsonfiles)

# Connect to VPP, specifying a client name
r = vpp.connect("ping-test")
print(r)  # Should print connection result

# Show VPP version
rv = vpp.api.show_version()
if isinstance(rv.version, bytes):
    version_str = rv.version.decode().rstrip("\x00")
else:
    version_str = rv.version.rstrip("\x00")

print("VPP version =", version_str)

# Display VPP interfaces
for intf in vpp.api.sw_interface_dump():
    if isinstance(intf.interface_name, bytes):
        print(intf.interface_name.decode())
    else:
        print(intf.interface_name)


# Define event callback handler
def papi_event_handler(msgname, result):
    print(msgname)
    print(result)


# Register event callback function
r = vpp.register_event_callback(papi_event_handler)

# Send subscription request for interface events
r = vpp.api.want_interface_events(enable_disable=True, pid=os.getpid())

# Sleep to allow VPP interface status updates
print("Waiting for interface events... (press Ctrl+C to exit)")
try:
    while True:
        time.sleep(1)  # Keep the script running to receive events
except KeyboardInterrupt:
    print("\nExiting...")

# Unsubscribe from interface events
r = vpp.api.want_interface_events(enable_disable=False, pid=os.getpid())

# Disconnect from VPP
r = vpp.disconnect()
print(r)

exit(r)
