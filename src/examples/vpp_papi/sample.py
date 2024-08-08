#! /usr/bin/env python3

"""
Sample source code to use VPP's ACL API from Python (vpp_papi).

Make sure you have the rw rights on vpp's socket file (VPP_API_SOCKET).

Install vpp_papi and run this script:
    virtualenv venv-vpp
    source venv-vpp/bin/activate
    python3 -m pip install vpp_papi
    python3 sample.py
    deactivate
"""

import ipaddress
import logging
import pprint

from vpp_papi import VPPApiJSONFiles
from vpp_papi import vpp_format
from vpp_papi import vpp_papi

VPP_API_SOCKET = "/run/vpp/api.sock"
VPP_JSON_DIR = "/usr/share/vpp/api"
VPP_CLIENT_ID = "vpp_papi"

LOG = logging.getLogger(VPP_CLIENT_ID)
logging.basicConfig(level=logging.INFO)


def connect_vpp(jsonfiles):
    # Starting from vpp_papi 2.1.0 (https://pypi.org/project/vpp-papi/2.1.0/)
    # and vpp commit ac0babd412 (included in v24.06) we can download the API
    # definition files from the API itself.

    # vpp = vpp_papi.VPPApiClient(
    #     server_address=VPP_API_SOCKET,
    #     bootstrapapi=True,
    # )

    # But until then we have to provide the same set of files as the server
    # side has:

    vpp = vpp_papi.VPPApiClient(
        server_address=VPP_API_SOCKET,
        apifiles=jsonfiles,
    )

    vpp.connect(VPP_CLIENT_ID)
    return vpp


def get_or_create_loop_interface(index=0):
    sw_if_index = None
    # try creating
    reply = vpp.api.create_loopback_instance(is_specified=True, user_instance=index)
    if reply.retval == 0:
        # created now
        return reply.sw_if_index
    else:
        # could not create because existed already
        for intf in vpp.api.sw_interface_dump(name_filter=f"loop{index}"):
            # name_filter is a substring match, therefore
            # we still need to check for equality
            if intf.interface_name == f"loop{index}":
                return intf.sw_if_index
    raise f"could neither get nor create loop{index}"


def acl_examples():
    # get plugin version
    v = vpp.api.acl_plugin_get_version()
    print(f"acl plugin version: {v.major}.{v.minor}")

    # delete acls
    for acl in vpp.api.acl_dump(acl_index=0xFFFFFFFF):  # 0xFFFFFFFF == all
        vpp.api.acl_del(acl_index=acl.acl_index)

    # some acl rules
    acl_rules = [
        {
            "is_permit": 0,  # 0 == DENY
            "src_prefix": ipaddress.IPv4Network("1.2.3.0/24"),
            "dst_prefix": ipaddress.IPv4Network("0.0.0.0/0"),
            "proto": 1,  # 1 == ICMP
            "srcport_or_icmptype_first": 0,
            "srcport_or_icmptype_last": 65535,
            "dstport_or_icmpcode_first": 0,
            "dstport_or_icmpcode_last": 65535,
            "tcp_flags_mask": 0,
            "tcp_flags_value": 0,
        },
    ]

    # create an acl with the rules above
    reply = vpp.api.acl_add_replace(
        acl_index=0xFFFFFFFF,  # 0xFFFFFFFF == add
        tag="vpp_papi",
        count=len(acl_rules),
        r=acl_rules,
    )
    acl_index = reply.acl_index

    # print all acls
    print("acl_dump:")
    for acl in vpp.api.acl_dump(acl_index=0xFFFFFFFF):  # 0xFFFFFFFF == all
        print(acl)

    # get (or create) loop0's index
    sw_if_index = get_or_create_loop_interface(index=0)

    # apply the above acl to loop0
    vpp.api.acl_interface_set_acl_list(
        sw_if_index=sw_if_index,
        n_input=0,
        count=1,
        acls=[acl_index],
    )

    # print all interface-acl associations
    print("acl_interface_list_dump:")
    pprint.pprint(vpp.api.acl_interface_list_dump())


vpp = connect_vpp(VPPApiJSONFiles.find_api_files(api_dir=VPP_JSON_DIR))
print(f"vpp version: {vpp.api.show_version().version}")
acl_examples()
vpp.disconnect()
