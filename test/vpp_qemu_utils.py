#!/usr/bin/env python

# Utility functions for QEMU tests ##

import subprocess
import sys
import os
import multiprocessing as mp


def can_create_namespaces():
    """Check if the environment allows creating the namespaces"""

    try:
        namespace = "vpp_chk_4212"
        result = subprocess.run(["ip", "netns", "add", namespace], capture_output=True)
        if result.returncode != 0:
            return False
        result = subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
        if result.returncode != 0:
            return False
        return True
    except:
        return False


def create_namespace(ns):
    """create one or more namespaces.

    arguments:
    ns -- a string value or an iterable of namespace names
    """
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns
    try:
        for namespace in namespaces:
            result = subprocess.run(["ip", "netns", "add", namespace])
            if result.returncode != 0:
                raise Exception(f"Error while creating namespace {namespace}")
    except subprocess.CalledProcessError as e:
        raise Exception("Error creating namespace:", e.output)


def add_namespace_route(ns, prefix, gw_ip):
    """Add a route to a namespace.

    arguments:
    ns -- namespace string value
    prefix -- NETWORK/MASK or "default"
    gw_ip -- Gateway IP
    """
    try:
        subprocess.run(
            ["ip", "netns", "exec", ns, "ip", "route", "add", prefix, "via", gw_ip],
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        raise Exception("Error adding route to namespace:", e.output)


def delete_host_interfaces(*host_interface_names):
    """Delete host interfaces.

    arguments:
    host_interface_names - sequence of host interface names to be deleted
    """
    for host_interface_name in host_interface_names:
        try:
            subprocess.run(
                ["ip", "link", "del", host_interface_name], capture_output=True
            )
        except subprocess.CalledProcessError as e:
            raise Exception("Error deleting host interface:", e.output)


def create_host_interface(
    host_interface_name, vpp_interface_name, host_namespace, *host_ip_prefixes
):
    """Create a host interface of type veth.

    arguments:
    host_interface_name -- name of the veth interface on the host side
    vpp_interface_name -- name of the veth interface on the VPP side
    host_namespace -- host namespace into which the host_interface needs to be set
    host_ip_prefixes -- a sequence of ip/prefix-lengths to be set
                        on the host_interface
    """
    try:
        process = subprocess.run(
            [
                "ip",
                "link",
                "add",
                "name",
                vpp_interface_name,
                "type",
                "veth",
                "peer",
                "name",
                host_interface_name,
            ],
            capture_output=True,
        )
        if process.returncode != 0:
            print(f"Error creating host interface: {process.stderr}")
            sys.exit(1)

        process = subprocess.run(
            ["ip", "link", "set", host_interface_name, "netns", host_namespace],
            capture_output=True,
        )
        if process.returncode != 0:
            print(f"Error setting host interface namespace: {process.stderr}")
            sys.exit(1)

        process = subprocess.run(
            ["ip", "link", "set", "dev", vpp_interface_name, "up"], capture_output=True
        )
        if process.returncode != 0:
            print(f"Error bringing up the host interface: {process.stderr}")
            sys.exit(1)

        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                host_namespace,
                "ip",
                "link",
                "set",
                "dev",
                host_interface_name,
                "up",
            ],
            capture_output=True,
        )
        if process.returncode != 0:
            print(
                f"Error bringing up the host interface in namespace: "
                f"{process.stderr}"
            )
            sys.exit(1)

        for host_ip_prefix in host_ip_prefixes:
            process = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    host_namespace,
                    "ip",
                    "addr",
                    "add",
                    host_ip_prefix,
                    "dev",
                    host_interface_name,
                ],
                capture_output=True,
            )
            if process.returncode != 0:
                print(
                    f"Error setting ip prefix on the host interface: "
                    f"{process.stderr}"
                )
                sys.exit(1)
    except subprocess.CalledProcessError as e:
        raise Exception("Error adding route to namespace:", e.output)


def set_interface_mtu(namespace, interface, mtu, logger):
    """set an mtu number on a linux device interface."""
    args = ["ip", "link", "set", "mtu", str(mtu), "dev", interface]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    try:
        logger.debug(
            f"Setting mtu:{mtu} on linux interface:{interface} "
            f"in namespace:{namespace}"
        )
        subprocess.run(args)
    except subprocess.CalledProcessError as e:
        raise Exception("Error updating mtu:", e.output)


def enable_interface_gso(namespace, interface):
    """enable gso offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "on", "tx", "on"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    try:
        process = subprocess.run(args, capture_output=True)
        if process.returncode != 0:
            print(
                f"Error enabling GSO offload on linux device interface: "
                f"{process.stderr}"
            )
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        raise Exception("Error enabling gso:", e.output)


def disable_interface_gso(namespace, interface):
    """disable gso offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "off", "tx", "off"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    try:
        process = subprocess.run(args, capture_output=True)
        if process.returncode != 0:
            print(
                f"Error disabling GSO offload on linux device interface: "
                f"{process.stderr}"
            )
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        raise Exception("Error disabling gso:", e.output)


def delete_namespace(namespaces):
    """delete one or more namespaces.

    arguments:
    namespaces -- a list of namespace names
    """
    try:
        for namespace in namespaces:
            result = subprocess.run(
                ["ip", "netns", "del", namespace], capture_output=True
            )
            if result.returncode != 0:
                raise Exception(f"Error while deleting namespace {namespace}")
    except subprocess.CalledProcessError as e:
        raise Exception("Error deleting namespace:", e.output)


def list_namespace(ns):
    """List the IP address of a namespace"""
    try:
        subprocess.run(["ip", "netns", "exec", ns, "ip", "addr"])
    except subprocess.CalledProcessError as e:
        raise Exception("Error listing namespace IP:", e.output)


def libmemif_test_app(memif_sock_path, logger):
    """Build & run the libmemif test_app for memif interface testing."""
    test_dir = os.path.dirname(os.path.realpath(__file__))
    ws_root = os.path.dirname(test_dir)
    libmemif_app = os.path.join(
        ws_root, "extras", "libmemif", "build", "examples", "test_app"
    )

    def build_libmemif_app():
        if not os.path.exists(libmemif_app):
            print(f"Building app:{libmemif_app} for memif interface testing")
            libmemif_app_dir = os.path.join(ws_root, "extras", "libmemif", "build")
            if not os.path.exists(libmemif_app_dir):
                os.makedirs(libmemif_app_dir)
            os.chdir(libmemif_app_dir)
            try:
                p = subprocess.run(["cmake", ".."], capture_output=True)
                logger.debug(p.stdout)
                if p.returncode != 0:
                    print(f"libmemif app:{libmemif_app} cmake error:{p.stderr}")
                    sys.exit(1)
                p = subprocess.run(["make"], capture_output=True)
                logger.debug(p.stdout)
                if p.returncode != 0:
                    print(f"Error building libmemif app:{p.stderr}")
                    sys.exit(1)
            except subprocess.CalledProcessError as e:
                raise Exception("Error building libmemif_test_app:", e.output)

    def start_libmemif_app():
        """Restart once if the initial run fails."""
        max_tries = 2
        run = 0
        if not os.path.exists(libmemif_app):
            raise Exception(
                f"Error could not locate the libmemif test app:{libmemif_app}"
            )
        args = [libmemif_app, "-b", "9216", "-s", memif_sock_path]
        while run < max_tries:
            try:
                process = subprocess.run(args, capture_output=True)
                logger.debug(process.stdout)
                if process.returncode != 0:
                    msg = f"Error starting libmemif app:{libmemif_app}"
                    logger.error(msg)
                    raise Exception(msg)
            except Exception:
                msg = f"re-starting libmemif app:{libmemif_app}"
                logger.error(msg)
                continue
            else:
                break
            finally:
                run += 1

    build_libmemif_app()
    process = mp.Process(target=start_libmemif_app)
    process.start()
    return process
