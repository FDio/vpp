import os
import time
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

    @property
    def in_history_counter(self):
        """Self-incrementing counter used when renaming old pcap files"""
        v = self._in_history_counter
        self._in_history_counter += 1
        return v

    @property
    def out_history_counter(self):
        """Self-incrementing counter used when renaming old pcap files"""
        v = self._out_history_counter
        self._out_history_counter += 1
        return v

    def post_init_setup(self):
        """ Perform post-init setup for super class and add our own setup """
        super(VppPGInterface, self).post_init_setup()
        self._out_file = "pg%u_out.pcap" % self.sw_if_index
        self._out_path = self.test.tempdir + "/" + self._out_file
        self._in_file = "pg%u_in.pcap" % self.sw_if_index
        self._in_path = self.test.tempdir + "/" + self._in_file
        self._capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self._cap_name = "pcap%u" % self.sw_if_index
        self._input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.in_path, self.pg_index, self.cap_name)

    def __init__(self, test, pg_index):
        """ Create VPP packet-generator interface """
        self._in_history_counter = 0
        self._out_history_counter = 0
        self._pg_index = pg_index
        self._test = test
        r = self.test.vapi.pg_create_interface(self.pg_index)
        self._sw_if_index = r.sw_if_index
        self.post_init_setup()

    def enable_capture(self):
        """ Enable capture on this packet-generator interface"""
        try:
            if os.path.isfile(self.out_path):
                os.rename(self.out_path,
                          "%s/history.[timestamp:%f].[%s-counter:%04d].%s" %
                          (self.test.tempdir,
                           time.time(),
                           self.name,
                           self.out_history_counter,
                           self._out_file))
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
            if os.path.isfile(self.in_path):
                os.rename(self.in_path,
                          "%s/history.[timestamp:%f].[%s-counter:%04d].%s" %
                          (self.test.tempdir,
                           time.time(),
                           self.name,
                           self.in_history_counter,
                           self._in_file))
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
