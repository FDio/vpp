import os
from logging import error
from scapy.utils import wrpcap, rdpcap
from vpp_interface import VppInterface


class VppPGInterface(VppInterface):
    """
    VPP packet-generator interface

    @property pg_index: packet-generator interface index assigned by VPP
    @property out_path: file path to captured packets
    @property in_path: file path to injected packets
    @property capture_cli: CLI string to start capture on this interface
    @property cap_name: capture name for this interface
    @property input_cli: CLI string to load the injected packets
    """

    def post_init_setup(self):
        """ Perform post-init setup for super class and add our own setup """
        super(VppPGInterface, self).post_init_setup()
        self.out_path = "/tmp/pg%u_out.pcap" % self.sw_if_index
        self.in_path = "/tmp/pg%u_in.pcap" % self.sw_if_index
        self.capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self.cap_name = "pcap%u" % self.sw_if_index
        self.input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.in_path, self.pg_index, self.cap_name)

    def __init__(self, test, pg_index):
        """ Create VPP packet-generator interface """
        self.test = test
        self.pg_index = pg_index
        r = self.test.vapi.pg_create_interface(self.pg_index)
        self._sw_if_index = r.sw_if_index
        self.post_init_setup()

    def enable_capture(self):
        """ Enable capture on this packet-generator interface"""
        try:
            os.unlink(self.out_path)
        except:
            pass
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.capture_cli)

    def add_stream(self, pkts):
        """
        Add a stream of packets to this packet-generator

        :param pkts: iterable packets

        """
        try:
            os.remove(self.in_path)
        except:
            pass
        wrpcap(self.in_path, pkts)
        # FIXME this should be an API, but no such exists atm
        self.test.vapi.cli(self.input_cli)
        self.test.pg_streams.append(self.cap_name)
        self.test.vapi.cli("trace add pg-input %d" % len(pkts))

    def get_capture(self):
        """
        Get captured packets

        :returns: iterable packets
        """
        try:
            output = rdpcap(self.out_path)
        except IOError:  # TODO
            error("File %s does not exist, probably because no"
                  " packets arrived" % self.out_path)
            return []
        return output
