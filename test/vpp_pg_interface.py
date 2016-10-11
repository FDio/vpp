import os
from logging import error
from scapy.utils import wrpcap, rdpcap
from vpp_interface import VppInterface


class VppPGInterface(VppInterface):
    """
    VPP packet-generator interface
    """

    @property
    def pg_index(self):
        """packet-generator interface index assigned by VPP"""
        return self._pg_index

    @property
    def out_path(self):
        """pcap file path - captured packets"""
        return self._out_path

    @property
    def in_path(self):
        """ pcap file path - injected packets"""
        return self._in_path

    @property
    def capture_cli(self):
        """CLI string to start capture on this interface"""
        return self._capture_cli

    @property
    def cap_name(self):
        """capture name for this interface"""
        return self._cap_name

    @property
    def input_cli(self):
        """CLI string to load the injected packets"""
        return self._input_cli

    def post_init_setup(self):
        """ Perform post-init setup for super class and add our own setup """
        super(VppPGInterface, self).post_init_setup()
        self._out_path = self.test.tempdir + "/pg%u_out.pcap" % self.sw_if_index
        self._in_path = self.test.tempdir + "/pg%u_in.pcap" % self.sw_if_index
        self._capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self._cap_name = "pcap%u" % self.sw_if_index
        self._input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.in_path, self.pg_index, self.cap_name)

    def __init__(self, test, pg_index):
        """ Create VPP packet-generator interface """
        self._pg_index = pg_index
        self._test = test
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
