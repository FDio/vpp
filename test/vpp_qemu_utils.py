import subprocess
import sys
import os
import time
from multiprocessing import Lock, Process

lock = Lock()

def can_create_namespaces(namespace="vpp_chk_4212"):
    """Check if the environment allows creating the namespaces"""
    with lock:
        try:
            result = subprocess.run(["ip", "netns", "add", namespace], capture_output=True)
            if result.returncode != 0:
                return False
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
            return True
        except Exception:
            return False


def create_namespace(ns):
    """Create one or more namespaces."""
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns

    with lock:
        for namespace in namespaces:
            retries = 3
            for attempt in range(retries):
                result = subprocess.run(["ip", "netns", "add", namespace], capture_output=True)
                if result.returncode == 0:
                    break
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(f"Failed to create namespace {namespace} after {retries} attempts")


def add_namespace_route(ns, prefix, gw_ip):
    """Add a route to a namespace."""
    with lock:
        retries = 3
        for attempt in range(retries):
            result = subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "route", "add", prefix, "via", gw_ip],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise Exception(f"Failed to add route to namespace {ns} after {retries} attempts")


def delete_host_interfaces(*host_interface_names):
    """Delete host interfaces."""
    with lock:
        for host_interface_name in host_interface_names:
            retries = 3
            for attempt in range(retries):
                result = subprocess.run(["ip", "link", "del", host_interface_name], capture_output=True)
                if result.returncode == 0:
                    break
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(f"Failed to delete host interface {host_interface_name} after {retries} attempts")


def create_host_interface(host_interface_name, vpp_interface_name, host_namespace, *host_ip_prefixes):
    """Create a host interface of type veth."""
    with lock:
        retries = 3
        for attempt in range(retries):
            result = subprocess.run(
                ["ip", "link", "add", "name", vpp_interface_name, "type", "veth", "peer", "name", host_interface_name],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise Exception(f"Failed to create host interface {host_interface_name} after {retries} attempts")

        result = subprocess.run(["ip", "link", "set", host_interface_name, "netns", host_namespace], capture_output=True)
        if result.returncode != 0:
            raise Exception(f"Error setting host interface namespace: {result.stderr.decode()}")

        result = subprocess.run(["ip", "link", "set", "dev", vpp_interface_name, "up"], capture_output=True)
        if result.returncode != 0:
            raise Exception(f"Error bringing up the host interface: {result.stderr.decode()}")

        result = subprocess.run(
            ["ip", "netns", "exec", host_namespace, "ip", "link", "set", "dev", host_interface_name, "up"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise Exception(f"Error bringing up the host interface in namespace: {result.stderr.decode()}")

        for host_ip_prefix in host_ip_prefixes:
            result = subprocess.run(
                ["ip", "netns", "exec", host_namespace, "ip", "addr", "add", host_ip_prefix, "dev", host_interface_name],
                capture_output=True,
            )
            if result.returncode != 0:
                raise Exception(f"Error setting ip prefix on the host interface: {result.stderr.decode()}")


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
                raise Exception(f"Failed to set MTU on interface {interface} in namespace {namespace} after {retries} attempts")


def enable_interface_gso(namespace, interface):
    """Enable GSO offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "on", "tx", "on"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    with lock:
        result = subprocess.run(args, capture_output=True)
        if result.returncode != 0:
            raise Exception(f"Error enabling GSO offload on interface {interface} in namespace {namespace}: {result.stderr.decode()}")


def disable_interface_gso(namespace, interface):
    """Disable GSO offload on a linux device interface."""
    args = ["ethtool", "-K", interface, "rx", "off", "tx", "off"]
    if namespace:
        args = ["ip", "netns", "exec", namespace] + args
    with lock:
        result = subprocess.run(args, capture_output=True)
        if result.returncode != 0:
            raise Exception(f"Error disabling GSO offload on interface {interface} in namespace {namespace}: {result.stderr.decode()}")


def delete_namespace(ns):
    """Delete one or more namespaces."""
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns
    with lock:
        for namespace in namespaces:
            retries = 3
            for attempt in range(retries):
                result = subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
                if result.returncode == 0:
                    break
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(f"Failed to delete namespace {namespace} after {retries} attempts")


def list_namespace(ns):
    """List the IP address of a namespace."""
    with lock:
        result = subprocess.run(["ip", "netns", "exec", ns, "ip", "addr"], capture_output=True)
        if result.returncode != 0:
            raise Exception(f"Error listing IP addresses in namespace {ns}: {result.stderr.decode()}")


def libmemif_test_app(memif_sock_path, logger):
    """Build & run the libmemif test_app for memif interface testing."""
    test_dir = os.path.dirname(os.path.realpath(__file__))
    ws_root = os.path.dirname(test_dir)
    libmemif_app = os.path.join(ws_root, "extras", "libmemif", "build", "examples", "test_app")

    def build_libmemif_app():
        if not os.path.exists(libmemif_app):
            logger.info(f"Building app:{libmemif_app} for memif interface testing")
            libmemif_app_dir = os.path.join(ws_root, "extras", "libmemif", "build")
            os.makedirs(libmemif_app_dir, exist_ok=True)
            os.chdir(libmemif_app_dir)
            subprocess.run(["cmake", ".."], check=True)
            subprocess.run(["make"], check=True)

    def start_libmemif_app():
        max_tries = 2
        run = 0
        while run < max_tries:
            result = subprocess.run([libmemif_app, "-b", "9216", "-s", memif_sock_path], capture_output=True)
            if result.returncode == 0:
                break
            logger.error(f"Restarting libmemif app due to error: {result.stderr.decode()}")
            run += 1
            time.sleep(1)

    build_libmemif_app()
    process = Process(target=start_libmemif_app)
    process.start()
    return process
