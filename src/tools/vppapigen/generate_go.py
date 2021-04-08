#!/usr/bin/env python3

import os
import subprocess
import sys
import tarfile

import requests

#
# GoVPP API generator generates Go bindings compatible with the local
# VPP version and latest GoVPP https://gerrit.fd.io/r/admin/repos/govpp
# Bindings are based on JSON. Destination folder has to be set.
#   'GO_API_OUTPUT' - this variable sets the target folder (required)
#   'GO_API_FILES' - allows to filter APIs to generate
#


# Verifies GO_API_OUTPUT variable requirements are met
def validate_output_dir():
    if "GO_API_OUTPUT" in os.environ:
        output = os.environ['GO_API_OUTPUT']

        if output == "":
            print("'GO_API_OUTPUT' is empty, please set a valid path")
            sys.exit(1)

        if not os.path.exists(output):
            print("Output path does not exists, you have to create it first")
            sys.exit(1)

    else:
        print("Output directory was not defined, set 'GO_API_OUTPUT'")
        sys.exit(1)

    print("API output directory set by 'GO_API_OUTPUT' is " + output)
    return output


# Returns version of the installed Go
def get_go_version(go_root):
    p = subprocess.Popen(["./go", "version"],
                         cwd=go_root + "/bin",
                         stdout=subprocess.PIPE,
                         universal_newlines=True, )
    output, _ = p.communicate()
    output_fmt = output.replace("go version go", "", 1)

    return output_fmt.rstrip("\n")


# Returns version of the installed binary API generator
def get_binapi_gen_version(go_path):
    p = subprocess.Popen(["./binapi-generator", "-version"],
                         cwd=go_path + "/bin",
                         stdout=subprocess.PIPE,
                         universal_newlines=True, )
    output, _ = p.communicate()
    output_fmt = output.replace("govpp", "", 1)

    return output_fmt.rstrip("\n")


# Verifies local Go installation and installs the latest
# one if missing
def install_golang(go_root):
    go_bin = go_root + "/bin/go"

    if os.path.exists(go_bin) & os.path.isfile(go_bin):
        print('Go ' + get_go_version(go_root) + ' is already installed')
        return

    print("Go binary not found, installing the latest version...")
    go_folders = ['src', 'pkg', 'bin']

    for f in go_folders:
        if not os.path.exists(os.path.join(go_root, f)):
            os.makedirs(os.path.join(go_root, f))

    filename = requests.get('https://golang.org/VERSION?m=text').text + ".linux-amd64.tar.gz"
    url = "https://dl.google.com/go/" + filename
    r = requests.get(url)
    with open("/tmp/" + filename, 'wb') as f:
        f.write(r.content)

    go_tf = tarfile.open("/tmp/" + filename)
    # Strip /go dir from the go_root path as it will
    # be created while extracting the tar file
    go_root_head, _ = os.path.split(go_root)
    go_tf.extractall(path=go_root_head)
    go_tf.close()
    os.remove("/tmp/" + filename)

    print('Go ' + get_go_version(go_root) + 'was installed')


# Installs latest binary API generator
def install_binapi_gen(go_root, go_path):
    os.environ['GO111MODULE'] = "on"
    if os.path.exists(go_root + "/bin/go") & os.path.isfile(go_root + "/bin/go"):
        p = subprocess.Popen(["./go", "get", "git.fd.io/govpp.git/cmd/binapi-generator@master"],
                             cwd=go_root + "/bin",
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True, )
        _, error = p.communicate()
        if p.returncode != 0:
            print("binapi generator installation failed: %d %s" % (p.returncode, error))
    bg_ver = get_binapi_gen_version(go_path)
    print('Installed binary API generator ' + bg_ver)


# Creates generated bindings using GoVPP binapigen to the target folder
def generate_api(output_dir, vpp_dir, api_list, go_path):
    output_binapi = output_dir + "binapi" if output_dir[-1] == "/" else output_dir + "/binapi"
    json_dir = vpp_dir + "/build-root/install-vpp-native/vpp/share/vpp/api"

    if not os.path.exists(json_dir):
        print("JSON API files are missing. Call 'make json-api-files' first")
        return

    print("Generating API")
    if len(api_list):
        print("Following API files were requested by 'GO_API_FILES': " + api_list)
        print("Note that dependency requirements may generate additional API files")
        p = subprocess.Popen(["./binapi-generator", "--output-dir=" + output_binapi, "--input-dir=" + json_dir,
                              api_list],
                             cwd=go_path + "/bin",
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True, )
    else:
        p = subprocess.Popen(["./binapi-generator", "--output-dir=" + output_binapi, "--input-dir=" + json_dir],
                             cwd=go_path + "/bin",
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True, )

    out = p.communicate()[1]
    if p.returncode != 0:
        print("go api generate failed: %d %s" % (p.returncode, out))

    # Print nice output of the binapi generator
    for msg in out.split():
        if "=" in msg:
            print()
        print(msg, end=" ")

    print("\n")
    print("Go API bindings were generated to " + output_binapi)


def main():
    vpp_dir = os.getcwd()
    output_dir = validate_output_dir()

    apis = []
    if 'GO_API_FILES' in os.environ:
        apis = os.environ['GO_API_FILES']

    # go specific environment variables
    if "GOROOT" in os.environ:
        go_root = os.environ['GOROOT']
    else:
        go_root = os.environ['HOME'] + "/.go"
    if "GOPATH" in os.environ:
        go_path = os.environ['GOPATH']
    else:
        go_path = os.environ['HOME'] + "/go"

    install_golang(go_root)
    install_binapi_gen(go_root, go_path)
    generate_api(output_dir, vpp_dir, apis, go_path)


if __name__ == "__main__":
    main()
