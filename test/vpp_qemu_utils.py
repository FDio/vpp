#!/usr/bin/env python

# Start an iPerf connection stream between two Linux namespaces ##

import subprocess


def create_namespace(ns):
    try:
        subprocess.run(["ip", "netns", "add", ns])
    except subprocess.CalledProcessError as e:
        raise Exception('Error creating namespace:', e.output)


class VppIperf:
    """"Create an iPerf3 connection stream between two namespaces.

    Usage:
    iperf = VppIperf()                   # Create the iPerf Object
    iperf.client_ns = 'ns1'              # Client Namespace
    iperf.server_ns = 'ns2'              # Server Namespace
    iperf.server_ip = '10.0.0.102'       # Server IP Address
    iperf.start()                        # Start the connection stream

    Optional:
    iperf.duration = 15   # Time to transmit for in seconds (Default=10)

    ## Optionally set any iperf3 client & server args
    Example:
    # Run 4 parallel streams, write to logfile & bind to port 5202
    iperf.client_args='-P 4 --logfile /tmp/vpp-vm-tests/vpp_iperf.log -p 5202'
    iperf.server_args='-p 5202'
    """
    def __init__(self, server_ns=None, client_ns=None, server_ip=None):
        self.server_ns = server_ns
        self.client_ns = client_ns
        self.server_ip = server_ip
        self.duration = 10
        self.client_args = ''
        self.server_args = ''

    def ensure_init(self):
        if self.server_ns and self.client_ns and self.server_ip:
            return True
        else:
            raise Exception('Error: Cannot Start.'
                            'iPerf object has not been initialized')

    def start_iperf_server(self):
        print('Starting iPerf3 Server Daemon in Namespace ', self.server_ns)
        args = ["ip", "netns", "exec", self.server_ns,
                "iperf3", "-s", "-D", "-B", self.server_ip]
        args.extend(self.server_args.split())
        try:
            subprocess.run(args, stderr=subprocess.STDOUT,
                           timeout=self.duration+5, encoding='utf-8')
        except subprocess.TimeoutExpired as e:
            raise Exception("Error: Timeout expired for iPerf", e.output)

    def start_iperf_client(self):
        print('Starting iPerf3 Client in Namespace ', self.client_ns)
        args = ["ip", "netns", "exec", self.client_ns,
                "iperf3", "-c", self.server_ip, "-t", str(self.duration)]
        args.extend(self.client_args.split())
        try:
            subprocess.run(args, stderr=subprocess.STDOUT,
                           timeout=self.duration+5, encoding='utf-8')
        except subprocess.TimeoutExpired as e:
            raise Exception("Error: Timeout expired for iPerf", e.output)

    def start(self):
        """ Run iPerf and return True if successful"""
        self.ensure_init()
        try:
            self.start_iperf_server()
        except Exception as e:
            subprocess.run(["pkill", "iperf"])
            raise Exception('Error starting iPerf Server', e)

        try:
            self.start_iperf_client()
        except Exception as e:
            raise Exception('Error starting iPerf Client', e)
        subprocess.run(["pkill", "iperf"])


if __name__ == "__main__":
    # Run iPerf using default settings
    iperf = VppIperf()
    iperf.client_ns = 'ns1'
    iperf.server_ns = 'ns2'
    iperf.server_ip = '10.0.0.102'
    iperf.duration = 20
    iperf.start()
