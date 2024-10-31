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


def create_namespace(history_file, ns=None):
    """Create one or more namespaces."""

    with lock:
        namespaces = []
        retries = 5

        if ns is None:
            for retry in range(retries):
                suffix = "".join(random.choices(string.hexdigits, k=8))
                new_namespace_name = f"vpp_ns_{suffix}"
                # Check if the namespace already exists
                result = subprocess.run(
                    ["ip", "netns", "add", new_namespace_name],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    with open(history_file, "a") as ns_file:
                        ns_file.write(f"{new_namespace_name}\n")
                    return new_namespace_name
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
                    with open(history_file, "a") as ns_file:
                        ns_file.write(f"{namespace}\n")
                    break
                if attempt >= retries - 1:
                    raise Exception(
                        f"Failed to create namespace {namespace} after {retries} attempts. Error: {result.stderr.decode()}"
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


def delete_all_host_interfaces(history_file):
    """Delete all host interfaces whose names have been added to the history file."""

    with lock:
        if os.path.exists(history_file):
            with open(history_file, "r") as if_file:
                for line in if_file:
                    if_name = line.strip()
                    if if_name:
                        _delete_host_interfaces(if_name)
                os.remove(history_file)


def _delete_host_interfaces(*host_interface_names):
    """Delete host interfaces.
    arguments:
    host_interface_names - sequence of host interface names to be deleted
    """
    for host_interface_name in host_interface_names:
        retries = 3
        for attempt in range(retries):
            check_result = subprocess.run(
                ["ip", "link", "show", host_interface_name],
                capture_output=True,
                text=True,
            )
            if check_result.returncode != 0:
                break

            result = subprocess.run(
                ["ip", "link", "del", host_interface_name],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                break
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise Exception(
                    f"Failed to delete host interface {host_interface_name} after {retries} attempts"
                )


def create_host_interface(
    history_file, host_namespace, *host_ip_prefixes, vpp_if_name=None, host_if_name=None
):
    """Create a host interface of type veth.
    arguments:
    host_namespace -- host namespace into which the host_interface needs to be set
    host_ip_prefixes -- a sequence of ip/prefix-lengths to be set
                        on the host_interface
    vpp_if_name -- name of the veth interface on the VPP side
    host_if_name -- name of the veth interface on the host side
    """
    with lock:
        retries = 5

        for attempt in range(retries):
            if_name = (
                host_if_name
                or f"host_if_{''.join(random.choices(string.hexdigits, k=8))}"
            )
            new_vpp_if_name = (
                vpp_if_name or f"vppout{''.join(random.choices(string.hexdigits, k=8))}"
            )

            result = subprocess.run(
                [
                    "ip",
                    "link",
                    "add",
                    "name",
                    new_vpp_if_name,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    if_name,
                ],
                capture_output=True,
            )
            if result.returncode == 0:
                host_if_name = if_name
                vpp_if_name = new_vpp_if_name
                with open(history_file, "a") as if_file:
                    if_file.write(f"{host_if_name}\n")
                break
            if attempt >= retries - 1:
                raise Exception(
                    f"Failed to create host interface {if_name} and vpp {new_vpp_if_name} after {retries} attempts. Error: {result.stderr.decode()}"
                )

        result = subprocess.run(
            ["ip", "link", "set", host_if_name, "netns", host_namespace],
            capture_output=True,
        )
        if result.returncode != 0:
            raise Exception(
                f"Error setting host interface namespace: {result.stderr.decode()}"
            )

        result = subprocess.run(
            ["ip", "link", "set", "dev", vpp_if_name, "up"], capture_output=True
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
                host_if_name,
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
                    host_if_name,
                ],
                capture_output=True,
            )
            if result.returncode != 0:
                raise Exception(
                    f"Error setting ip prefix on the host interface: {result.stderr.decode()}"
                )

        return host_if_name, vpp_if_name


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


def delete_all_namespaces(history_file):
    """Delete all namespaces whose names have been added to the history file."""
    with lock:
        if os.path.exists(history_file):
            with open(history_file, "r") as ns_file:
                for line in ns_file:
                    ns_name = line.strip()
                    if ns_name:
                        _delete_namespace(ns_name)
                os.remove(history_file)


def _delete_namespace(ns):
    """Delete one or more namespaces.

    arguments:
    ns -- a list of namespace names or namespace
    """
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns

    existing_namespaces = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True
    ).stdout.splitlines()
    existing_namespaces = {line.split()[0] for line in existing_namespaces}

    for namespace in namespaces:
        if namespace not in existing_namespaces:
            continue

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
