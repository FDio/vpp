from vpp_papi.vpp_papi import VPPApiClient
import sys, getopt
import packetforge
import fnmatch
import os

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
    try:
        opts, args = getopt.getopt(
            argv, "hf:p:a:", ["help=", "file=", "pattern=", "actions="]
        )
    except getopt.GetoptError:
        print("flow_create.py -f <file> -p <pattern> -a <actions>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("flow_create.py -f <file> -p <pattern> -a <actions>")
            sys.exit()
        elif opt in ("-f", "--file"):
            actions = ""
            json_file = arg
            file_flag = True
        elif opt in ("-p", "--pattern") and not file_flag:
            pattern = arg
        elif opt in ("-a", "--actions"):
            actions = arg

    if not file_flag:
        result = packetforge.Forge(pattern, actions, False)
    else:
        result = packetforge.Forge(json_file, actions, True)
    return result


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

    # set inteface states
    vpp.api.sw_interface_set_flags(sw_if_index=1, flags=1)

    my_flow = Main(sys.argv[1:])
    print(my_flow)

    # add flow
    rv = vpp.api.flow_add_v2(flow=my_flow)
    flow_index = rv[3]
    print(rv)

    # enabled added flow
    rv = vpp.api.flow_enable(flow_index=flow_index, hw_if_index=1)
    print(rv)

# command example:
# python flow_create.py -p "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()" -a "redirect-to-queue 3"
