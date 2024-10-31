#!/usr/bin/env python

# Utility functions for QEMU tests ##

import subprocess
import sys
import os
import time
import random
import string
from multiprocessing import Lock, Process

lock = Lock()


# def generate_unique_host_interface_name(base_prefix="vpp_host_", retries=3):
#     """
#     Generate a unique host interface name based on the provided base prefix.
#     Ensures no collision by checking if the interface already exists.
#     Arguments:
#     base_prefix -- the prefix to use for the interface name (default is "vpp_host_")
#     retries -- number of retries for uniqueness (default is 3)
#     Returns:
#     A unique host interface name as a string.
#     Raises:
#     Exception if a unique namespace name could not be generated after retries attempts.
#     """
#     with lock:
#         for retry in range(retries):
#             suffix = "".join(random.choices(string.digits, k=7))
#             interface_name = f"{base_prefix}{suffix}"
#             # Check if the interface already exists
#             result = subprocess.run(
#                 ["ip", "link", "show"], capture_output=True, text=True
#             )
#             if result.returncode != 0:
#                 raise Exception("Failed to retrieve host interface list.")
#             # Parse the existing interfaces and check if our generated name is already in use
#             existing_interfaces = result.stdout
#             if interface_name not in existing_interfaces:
#                 return interface_name
#             # Optional delay to handle transient conflicts in parallel setups
#             time.sleep(0.1)
#         raise Exception(
#             f"Failed to generate a unique host interface name after {retries} attempts."
#         )


def can_create_namespaces(namespace="vpp_chk_4212"):
    """Check if the environment allows creating the namespaces"""
    with lock:
        try:
            result = subprocess.run(
                ["ip", "netns", "add", namespace], capture_output=True
            )
            if result.returncode != 0:
                return False
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
            return True
        except Exception:
            return False


def create_namespace(ns=None):
    """Create one or more namespaces."""

    with lock:
        namespaces = []
        retries = 3
        existing_namespaces = []

        if ns == None:
            for retry in range(retries):
                suffix = "".join(random.choices(string.digits, k=4))
                new_namespace_name = f"vpp_ns_{suffix}"
                # Check if the namespace already exists
                result = subprocess.run(
                    ["ip", "netns", "list"], capture_output=True, text=True
                )
                if result.returncode != 0:
                    raise Exception("Failed to retrieve namespace list.")
                # Parse the existing namespaces and check if our generated name is already in use
                existing_namespaces = result.stdout.splitlines()

                if new_namespace_name not in existing_namespaces:
                    ns = new_namespace_name
                    namespaces = [ns]
                    break
            if not namespaces:
                raise Exception(
                    f"Failed to generate a unique namespace name after {retries} attempts."
                )
        elif isinstance(ns, str):
            namespaces = [ns]
        else:
            namespaces = ns

        for namespace in namespaces:
            for attempt in range(retries):
                result = subprocess.run(
                    ["ip", "netns", "add", namespace],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    break
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(
                        f"Failed to create namespace {namespace} after {retries} attempts. Existing namespaces: {existing_namespaces}. {result.stderr.decode()}"
                    )
        return ns


def add_namespace_route(ns, prefix, gw_ip):
    """Add a route to a namespace.
    arguments:
    ns -- namespace string value
    prefix -- NETWORK/MASK or "default"
    gw_ip -- Gateway IP
    """
    with lock:
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
    with lock:
        for host_interface_name in host_interface_names:
            retries = 3
            for attempt in range(retries):
                check_result = subprocess.run(
                    ["ip", "link", "show", host_interface_name],
                    capture_output=True,
                    text=True,
                )
                if check_result.returncode != 0:
                    print(
                        f"Interface {host_interface_name} does not exist or is already deleted."
                    )
                    break

                result = subprocess.run(
                    ["ip", "link", "del", host_interface_name],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    print(f"Successfully deleted host interface: {host_interface_name}")
                    break
                else:
                    print(
                        f"Attempt {attempt + 1} to delete {host_interface_name} failed: {result.stderr}"
                    )

                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(
                        f"Failed to delete host interface {host_interface_name} after {retries} attempts"
                    )


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
    with lock:
        retries = 3
        for attempt in range(retries):
            result = subprocess.run(
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
            if result.returncode == 0:
                break
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise Exception(
                    f"Failed to create host interface {host_interface_name} after {retries} attempts"
                )

        result = subprocess.run(
            ["ip", "link", "set", host_interface_name, "netns", host_namespace],
            capture_output=True,
        )
        if result.returncode != 0:
            raise Exception(
                f"Error setting host interface namespace: {result.stderr.decode()}"
            )

        result = subprocess.run(
            ["ip", "link", "set", "dev", vpp_interface_name, "up"], capture_output=True
        )
        if result.returncode != 0:
            raise Exception(
                f"Error bringing up the host interface: {result.stderr.decode()}"
            )

        result = subprocess.run(
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
        if result.returncode != 0:
            raise Exception(
                f"Error bringing up the host interface in namespace: {result.stderr.decode()}"
            )

        for host_ip_prefix in host_ip_prefixes:
            result = subprocess.run(
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
            if result.returncode != 0:
                raise Exception(
                    f"Error setting ip prefix on the host interface: {result.stderr.decode()}"
                )


def set_interface_mtu(namespace, interface, mtu, logger):
    """Set an MTU number on a linux device interface."""
    args = ["ip", "link", "set", "mtu", str(mtu), "dev", interface]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    with lock:
        retries = 3
        for attempt in range(retries):
            result = subprocess.run(args, capture_output=True)
            if result.returncode == 0:
                break
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise Exception(
                    f"Failed to set MTU on interface {interface} in namespace {namespace} after {retries} attempts"
                )


def enable_interface_gso(namespace, interface):
    """Enable GSO offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "on", "tx", "on"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    with lock:
        result = subprocess.run(args, capture_output=True)
        if result.returncode != 0:
            raise Exception(
                f"Error enabling GSO offload on interface {interface} in namespace {namespace}: {result.stderr.decode()}"
            )


def disable_interface_gso(namespace, interface):
    """Disable GSO offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "off", "tx", "off"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    with lock:
        result = subprocess.run(args, capture_output=True)
        if result.returncode != 0:
            raise Exception(
                f"Error disabling GSO offload on interface {interface} in namespace {namespace}: {result.stderr.decode()}"
            )


def delete_namespace(ns):
    """Delete one or more namespaces.

    arguments:
    namespaces -- a list of namespace names
    """
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns
    with lock:
        for namespace in namespaces:
            retries = 3
            for attempt in range(retries):
                result = subprocess.run(
                    ["ip", "netns", "del", namespace], capture_output=True
                )
                if result.returncode == 0:
                    break
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(
                        f"Failed to delete namespace {namespace} after {retries} attempts"
                    )


def list_namespace(ns):
    """List the IP address of a namespace."""
    with lock:
        result = subprocess.run(
            ["ip", "netns", "exec", ns, "ip", "addr"], capture_output=True
        )
        if result.returncode != 0:
            raise Exception(
                f"Error listing IP addresses in namespace {ns}: {result.stderr.decode()}"
            )


def libmemif_test_app(memif_sock_path, logger):
    """Build & run the libmemif test_app for memif interface testing."""
    test_dir = os.path.dirname(os.path.realpath(__file__))
    ws_root = os.path.dirname(test_dir)
    libmemif_app = os.path.join(
        ws_root, "extras", "libmemif", "build", "examples", "test_app"
    )

    def build_libmemif_app():
        if not os.path.exists(libmemif_app):
            logger.info(f"Building app:{libmemif_app} for memif interface testing")
            libmemif_app_dir = os.path.join(ws_root, "extras", "libmemif", "build")
            os.makedirs(libmemif_app_dir, exist_ok=True)
            os.chdir(libmemif_app_dir)
            subprocess.run(["cmake", ".."], check=True)
            subprocess.run(["make"], check=True)

    def start_libmemif_app():
        """Restart once if the initial run fails."""
        max_tries = 2
        run = 0
        while run < max_tries:
            result = subprocess.run(
                [libmemif_app, "-b", "9216", "-s", memif_sock_path], capture_output=True
            )
            if result.returncode == 0:
                break
            logger.error(
                f"Restarting libmemif app due to error: {result.stderr.decode()}"
            )
            run += 1
            time.sleep(1)

    build_libmemif_app()
    process = Process(target=start_libmemif_app)
    process.start()
    return process
