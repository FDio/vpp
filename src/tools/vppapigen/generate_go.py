#!/usr/bin/env python3

import argparse
import os
import pathlib
import subprocess
import tarfile
import shutil

import requests
import sys

#
# GoVPP API generator generates Go bindings compatible with the local VPP
#

DefaultGoVppCommit = "16a47ef937b3a5ce6acf45885386062b323c8d25"


def version_geq(ver_a, ver_b):
    major_a, minor_a, patch_a = ver_a.split(".")
    major_b, minor_b, patch_b = ver_b.split(".")
    if major_a > major_b:
        return True
    elif major_a == major_b and minor_a > minor_b:
        return True
    elif major_a == major_b and minor_a == minor_b and patch_a >= patch_b:
        return True
    return False


def execute(cli, cwd=None):
    p = subprocess.Popen(
        cli.split(),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    output, error = p.communicate()
    if p.returncode != 0:
        print("Command `%s` failed: %d %s" % (cli, p.returncode, error))
        sys.exit(1)
    return output, error


def get_go_version(go_root):
    # Returns version of the installed Go
    output, _ = execute("./go version", cwd=go_root + "/bin")
    return output.replace("go version go", "", 1).rstrip("\n")


# Returns version of the installed binary API generator
def get_binapi_gen_version(go_path):
    output, _ = execute("./binapi-generator -version", cwd=go_path + "/bin")
    return output.replace("govpp", "", 1).rstrip("\n")


# Verifies local Go installation and installs the latest
# one if missing
def install_golang(go_root):
    go_bin = go_root + "/bin/go"

    if os.path.exists(go_bin) and os.path.isfile(go_bin):
        print("Go " + get_go_version(go_root) + " is already installed")
        return

    filename = (
        requests.get("https://golang.org/VERSION?m=text").text + ".linux-amd64.tar.gz"
    )
    url = "https://dl.google.com/go/" + filename

    print("Go binary not found, installing the latest version...")
    print("Download url      = %s" % url)
    print("Install directory = %s" % go_root)
    text = input("[Y/n] ?")

    if text.strip().lower() != "y" and text.strip().lower() != "yes":
        print("Aborting...")
        exit(1)

    go_folders = ["src", "pkg", "bin"]

    for f in go_folders:
        if not os.path.exists(os.path.join(go_root, f)):
            os.makedirs(os.path.join(go_root, f))
    r = requests.get(url)
    with open("/tmp/" + filename, "wb") as f:
        f.write(r.content)

    go_tf = tarfile.open("/tmp/" + filename)
    # Strip /go dir from the go_root path as it will
    # be created while extracting the tar file
    go_root_head, _ = os.path.split(go_root)
    go_tf.extractall(path=go_root_head)
    go_tf.close()
    os.remove("/tmp/" + filename)

    print("Go " + get_go_version(go_root) + " was installed")


# Installs latest binary API generator
def install_binapi_gen(c, go_root, go_path):
    go_version = get_go_version(go_root)
    if version_geq(go_version, "1.18.0"):
        execute(
            "./go install git.fd.io/govpp.git/cmd/binapi-generator@" + c,
            cwd=go_root + "/bin",
        )
    else:
        os.environ["GO111MODULE"] = "on"
        execute(
            "./go get git.fd.io/govpp.git/cmd/binapi-generator@" + c,
            cwd=go_root + "/bin",
        )
    bg_ver = get_binapi_gen_version(go_path)
    print("Installed binary API generator " + bg_ver)


# Creates generated bindings using GoVPP binapigen to the target folder
def generate_api(output_dir, vpp_dir, api_list, import_prefix, no_source, go_path):
    json_dir = vpp_dir + "/build-root/install-vpp-native/vpp/share/vpp/api"

    if not os.path.exists(json_dir):
        print("Missing JSON api definitions")
        sys.exit(1)

    print("Generating API")
    cmd = ["./binapi-generator", "--input-dir=" + json_dir]
    if output_dir:
        cmd += ["--output-dir=" + output_dir]
    if len(api_list):
        print("Following API files were requested by 'GO_API_FILES': " + str(api_list))
        print("Note that dependency requirements may generate additional API files")
        cmd.append(api_list)
    if import_prefix:
        cmd.append("-import-prefix=" + import_prefix)
    if no_source:
        cmd.append("-no-source-path-info")

    _, out = execute(" ".join(cmd), cwd=go_path + "/bin")
    # Print nice output of the binapi generator
    for msg in out.split():
        if "=" in msg:
            print()
        print(msg, end=" ")

    print("\n")
    print("Go API bindings were generated to " + output_dir)


def get_go_variables():
    # go specific environment variables
    if "GOROOT" in os.environ:
        go_root = os.environ["GOROOT"]
    else:
        go_binary = shutil.which("go")
        if go_binary != "":
            go_binary_dir, _ = os.path.split(go_binary)
            go_root = os.path.join(go_binary_dir, "..")
        else:
            go_root = os.environ["HOME"] + "/.go"
    if "GOPATH" in os.environ:
        go_path = os.environ["GOPATH"]
    else:
        go_path = os.environ["HOME"] + "/go"

    return go_root, go_path


def main():
    # project root directory
    root = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    vpp_dir = root.parent.parent.parent

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-govpp-commit",
        "--govpp-commit",
        help="GoVPP commit or branch ",
        default=DefaultGoVppCommit,
        type=str,
    )
    parser.add_argument(
        "-output-dir",
        "--output-dir",
        help="output target directory for generated bindings",
        type=str,
        default=os.path.join(vpp_dir, "vppbinapi"),
    )
    parser.add_argument(
        "-api-files",
        "--api-files",
        help="api files to generate (without commas)",
        nargs="+",
        type=str,
        default=[],
    )
    parser.add_argument(
        "-import-prefix",
        "--import-prefix",
        help="prefix imports in the generated go code",
        default="",
        type=str,
    )
    parser.add_argument(
        "-no-source-path-info",
        "--no-source-path-info",
        help="disable source path info in generated files",
        nargs="?",
        const=True,
        default=True,
    )
    args = parser.parse_args()

    go_root, go_path = get_go_variables()
    install_golang(go_root)

    if not (
        os.path.exists(go_root + "/bin/go") and os.path.isfile(go_root + "/bin/go")
    ):
        print(go_root + "/bin/go does not exist")
        sys.exit(1)

    install_binapi_gen(args.govpp_commit, go_root, go_path)
    generate_api(
        args.output_dir,
        str(vpp_dir),
        args.api_files,
        args.import_prefix,
        args.no_source_path_info,
        go_path,
    )


if __name__ == "__main__":
    main()
