#!/usr/bin/env python

# Start an iPerf connection stream between two Linux namespaces ##

import subprocess
import os
import sys
import tempfile
import time
from asfframework import VppAsfTestCase
from config import available_cpus


def set_iperf_affinity(cpus):
    """Move an iperf child away from the test driver's VPP CPU."""
    if cpus:
        os.sched_setaffinity(0, set(cpus))
    else:
        os.sched_setaffinity(0, available_cpus)


class VppIperf:
    """ "Create an iPerf connection stream between two namespaces.

    Usage:
    iperf = VppIperf()                   # Create the iPerf Object
    iperf.client_ns = 'ns1'              # Client Namespace
    iperf.server_ns = 'ns2'              # Server Namespace
    iperf.server_ip = '10.0.0.102'       # Server IP Address
    iperf.start()                        # Start the connection stream

    Optional:
    iperf.duration = 15   # Time to transmit for in seconds (Default=10)

    ## Optionally set any iperf client & server args
    Example:
    # Run 4 parallel streams, write to logfile & bind to port 5202
    iperf.client_args='-P 4 --logfile /tmp/vpp-vm-tests/vpp_iperf.log -p 5202'
    iperf.server_args='-p 5202'
    """

    def __init__(self, server_ns=None, client_ns=None, server_ip=None, logger=None):
        self.server_ns = server_ns
        self.client_ns = client_ns
        self.server_ip = server_ip
        self.duration = 10
        self.timeout_delay = 20
        self.server_start_timeout = 3
        self.client_retries = 3
        self.client_retry_delay = 3
        self.client_connect_timeout = "3000"
        self.client_args = ""
        self.server_args = ""
        self.logger = logger
        self.cpus = None
        # Set the iperf executable
        self.iperf = self.get_iperf()

    def ensure_init(self):
        if self.server_ns and self.client_ns and self.server_ip:
            return True
        else:
            raise Exception(
                "Error: Cannot Start." "iPerf object has not been initialized"
            )

    def get_iperf(self):
        """Return the iperf executable for running tests.

        Look for the iperf executable in the following order
        1. ${TEST_DATA_DIR}/usr/bin/iperf  # running tests inside the VM
        2. /usr/bin/iperf3                 # running tests on the host
        """
        vm_test_dir = os.getenv("TEST_DATA_DIR", "/tmp/vpp-vm-tests")
        if os.path.isdir(vm_test_dir):
            iperf = os.path.join(vm_test_dir, "/usr/bin/iperf")
        else:
            iperf = "/usr/bin/iperf3"
        if os.path.exists(iperf):
            return iperf
        else:
            self.logger.error(f"Could not find an iperf executable for running tests")
            sys.exit(1)

    def start_iperf_server(self):
        """Start an iperf server and return its process once it is listening."""
        netns = ["ip", "netns", "exec", self.server_ns]
        args = netns + [self.iperf, "-s"]
        args.extend(self.server_args.split())
        self.logger.debug("Starting iperf server: %s", " ".join(args))
        with tempfile.TemporaryFile() as log:
            # Keep the server in the foreground so readiness and cleanup can
            # both use the PID of this test's process.
            server = subprocess.Popen(
                args,
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda: set_iperf_affinity(self.cpus),
            )
            try:
                self.wait_for_iperf_server(server, netns)
                return server
            except BaseException:
                stop_iperf(server)
                log.seek(0)
                self.logger.error(
                    "iperf server output: %s",
                    log.read(4096).decode(errors="replace"),
                )
                raise

    def wait_for_iperf_server(self, server, netns):
        deadline = time.monotonic() + self.server_start_timeout
        while server.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # Observe the socket without making a client connection. Check
            # ownership because another process can be listening in the netns.
            try:
                sockets = subprocess.run(
                    netns + ["ss", "-H", "-lntup"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired:
                break
            if f"pid={server.pid}," in sockets.stdout and server.poll() is None:
                return
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        if server.returncode is not None:
            raise RuntimeError(f"iperf server exited with status {server.returncode}")
        raise TimeoutError(f"iperf server did not listen in namespace {self.server_ns}")

    @staticmethod
    def _to_text(value):
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def start_iperf_client(self):
        args = [
            "ip",
            "netns",
            "exec",
            self.client_ns,
            self.iperf,
            "-c",
            self.server_ip,
            "-t",
            str(self.duration),
        ]
        args.extend(self.client_args.split())
        if os.path.basename(self.iperf) == "iperf3" and "--connect-timeout" not in args:
            args.extend(["--connect-timeout", self.client_connect_timeout])
        cmd = " ".join(args)
        for attempt in range(1, self.client_retries + 1):
            try:
                result = subprocess.run(
                    args,
                    timeout=self.duration + self.timeout_delay,
                    encoding="utf-8",
                    capture_output=True,
                    preexec_fn=lambda: set_iperf_affinity(self.cpus),
                )
                transient_error = "unable to connect to server" in (
                    (result.stderr or "").lower()
                )
                if transient_error and attempt < self.client_retries:
                    self.logger.warning(
                        f"iPerf client connect failed (attempt {attempt}/{self.client_retries}): {cmd}"
                    )
                    VppAsfTestCase.sleep(self.client_retry_delay)
                    continue
                return result
            except subprocess.TimeoutExpired as e:
                if attempt < self.client_retries:
                    self.logger.warning(
                        f"iPerf client timeout (attempt {attempt}/{self.client_retries}): {cmd}"
                    )
                    VppAsfTestCase.sleep(self.client_retry_delay)
                    continue
                raise Exception(
                    "Error: Timeout expired for iPerf client",
                    self._to_text(e.output) + self._to_text(e.stderr),
                )

    def start(self, server_only=False, client_only=False):
        """Runs iPerf.

        Starts the iperf server or runs the iperf client.
        arguments:-
        server_only -- start the iperf server daemon only
        client_only -- run the iperf client only
        Return True if we have no errors in iPerf client, else False.
        """
        self.ensure_init()
        if not client_only:
            return self.start_iperf_server()
        if not server_only:
            result = self.start_iperf_client()
            self.logger.debug(f"Iperf client args: {result.args}")
            self.logger.debug(result.stdout)
            if result.returncode != 0 or result.stderr:
                self.logger.error(
                    f"Error starting Iperf Client in Namespace: {self.client_ns}"
                )
                self.logger.error(f"Iperf client args: {result.args}")
                self.logger.error(f"Iperf client returncode: {result.returncode}")
                self.logger.error(f"Iperf client has errors: {result.stderr}")
                return False
            else:
                return True


## Functions to start and stop iPerf using the iPerf object
def start_iperf(
    ip_version,
    client_ns="iprf_client_ns",
    server_ns="iprf_server_ns",
    server_ipv4_address="10.0.0.102",
    server_ipv6_address="2001:1::2",
    client_args="",
    server_args="",
    duration=10,
    server_only=False,
    client_only=False,
    logger=None,
    cpus=None,
):
    """Start an iperf connection stream using the iPerf object.

    Starts iPerf an connection stream between an iPerf client in the
    client namespace (client_ns) and a server in another
    namespace (server_ns).
    Parameters:
    ip_version - 4 or 6
    client_ns - iPerf client namespace
    server_ns - iPerf server namespace
    server_ipv4_address - ipv4 address of the server, if ip_version=4
    server_ipv6_address - ipv6 address of the server, if ip_version=6
    client_args - Additonal iperf control arguments to be passed
                    to the iperf client from the test (str)
    server_args - Additonal iperf control arguments to be passed
                    to the iperf server from the test (str)
    duration    - Iperf duration in seconds
    server_only - start iperf server only
    client_only - start the iperf client only
    logger - test logger
    cpus - CPUs on which to run the iPerf process
    """
    iperf = VppIperf()
    is_iperf3 = os.path.basename(iperf.iperf) == "iperf3"
    if ip_version == 4:
        iperf_server_ip = server_ipv4_address
        if is_iperf3:
            client_args = f"-4 {client_args}"
            server_args = f"-4 {server_args}"
    elif ip_version == 6:
        iperf_server_ip = server_ipv6_address
        if is_iperf3:
            # In iperf3, -6 selects IPv6 while -V only enables verbose output.
            client_args = f"-6 {client_args}"
            server_args = f"-6 {server_args}"
        else:
            # Legacy iperf uses -V for IPv6.
            client_args = f"-V {client_args}"
            server_args = f"-V {server_args}"
    iperf.client_ns = client_ns
    iperf.server_ns = server_ns
    iperf.server_ip = iperf_server_ip
    iperf.client_args = client_args
    iperf.server_args = server_args
    iperf.duration = duration
    iperf.logger = logger
    iperf.cpus = cpus
    return iperf.start(server_only=server_only, client_only=client_only)


def stop_iperf(server):
    """Stop and reap the iperf server started by this test."""
    server.terminate()
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()


if __name__ == "__main__":
    # Run iPerf using default settings
    iperf = VppIperf()
    iperf.client_ns = "ns1"
    iperf.server_ns = "ns2"
    iperf.server_ip = "10.0.0.102"
    iperf.duration = 20
    iperf.start()
