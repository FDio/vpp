# Copyright (c) 2022 Intel and/or its affiliates.
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

from vpp_papi.vpp_papi import VPPApiClient
import sys, getopt
import packetforge
import fnmatch
import os

# Get VPP json API file directory
CLIENT_ID = "Vppclient"
VPP_JSON_DIR = (
    os.path.abspath("../..") + "/build-root/install-vpp-native/vpp/share/vpp/api/core"
)
VPP_JSON_DIR_PLUGIN = (
    os.path.abspath("../..")
    + "/build-root/install-vpp-native/vpp/share/vpp/api/plugins"
)
API_FILE_SUFFIX = "*.api.json"


def Main(argv):
    file_flag = False
    operation = None
    show_result_only = False
    try:
        opts, args = getopt.getopt(
            argv,
            "hf:p:a:i:I:s",
            [
                "help",
                "add",
                "del",
                "file=",
                "pattern=",
                "actions=",
                "interface=",
                "flow-index=",
                "show-result-only"
            ],
        )
    except getopt.GetoptError:
        print(
            "flow_create.py --add|del -f <file> -p <pattern> -a <actions> -i <interface> -I <flow-index> -s <show-result-only>"
        )
        sys.exit()
    for opt, arg in opts:
        if opt == "-h":
            print(
                "flow_create.py --add|del -f <file> -p <pattern> -a <actions> -i <interface> -I <flow-index> -s <show-result-only>"
            )
            sys.exit()
        elif opt == "--add":
            operation = "add"
        elif opt == "--del":
            operation = "del"
        elif opt in ("-f", "--file"):
            actions = ""
            json_file = arg
            file_flag = True
        elif opt in ("-p", "--pattern") and not file_flag:
            pattern = arg
        elif opt in ("-a", "--actions"):
            actions = arg
        elif opt in ("-i", "--interface"):
            iface = arg
        elif opt in ("-I", "--flow-index"):
            flow_index = arg
        elif opt in ("-s", "--show-result-only"):
            show_result_only = True

    if operation == None:
        print("Error: Please choose the operation: add or del")
        sys.exit()

    if operation == "add":
        if not file_flag:
            result = packetforge.Forge(pattern, actions, False)
        else:
            result = packetforge.Forge(json_file, actions, True)
        return result, int(iface), operation, None, show_result_only
    elif operation == "del":
        return None, int(iface), operation, int(flow_index), show_result_only


def load_json_api_files(suffix=API_FILE_SUFFIX):
    jsonfiles = []
    json_dir = VPP_JSON_DIR
    for root, dirnames, filenames in os.walk(json_dir):
        for filename in fnmatch.filter(filenames, suffix):
            jsonfiles.append(os.path.join(json_dir, filename))
    json_dir = VPP_JSON_DIR_PLUGIN
    for root, dirnames, filenames in os.walk(json_dir):
        for filename in fnmatch.filter(filenames, suffix):
            jsonfiles.append(os.path.join(json_dir, filename))
    if not jsonfiles:
        raise RuntimeError("Error: no json api files found")
    else:
        print("load json api file done")
    return jsonfiles


def connect_vpp(jsonfiles):
    vpp = VPPApiClient(apifiles=jsonfiles)
    r = vpp.connect("CLIENT_ID")
    print("VPP api opened with code: %s" % r)
    return vpp


if __name__ == "__main__":
    # Python API need json definitions to interpret messages
    vpp = connect_vpp(load_json_api_files())
    print(vpp.api.show_version())

    # Parse the arguments
    my_flow, iface, operation, del_flow_index, show_result_only = Main(sys.argv[1:])

    # set inteface states
    vpp.api.sw_interface_set_flags(sw_if_index=iface, flags=1)

    if operation == "add":
        if (show_result_only):
            print(my_flow)
        else:
            # add flow
            rv = vpp.api.flow_add_v2(flow=my_flow)
            flow_index = rv[3]
            print(rv)

            # enable added flow
            rv = vpp.api.flow_enable(flow_index=flow_index, hw_if_index=iface)
            ena_res = rv[2]
            # if enable flow fail, delete added flow
            if ena_res:
                print("Error: enable flow failed, delete flow")
                rv = vpp.api.flow_del(flow_index=flow_index)
            print(rv)

    elif operation == "del":
        if (show_result_only):
            print("Cannot show spec and mask only in deletion")
        else:
            # disable flow
            rv = vpp.api.flow_disable(flow_index=del_flow_index, hw_if_index=iface)
            dis_res = rv[2]
            if dis_res:
                print("Error: disable flow failed")
                sys.exit()
            print(rv)

            # delete flow
            rv = vpp.api.flow_del(flow_index=del_flow_index)
            print(rv)

# command example:
# python flow_create.py --add -p "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()" -a "redirect-to-queue 3" -i 1
# python flow_create.py --del -i 1 -I 0
