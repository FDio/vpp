#!/usr/bin/env python3
import unittest
from ipaddress import ip_interface
from vpp_qemu_utils import create_namespace, VppIperf
from framework import VppTestCase, VppTestRunner


class TestTapQemu(VppTestCase):
    """ Test Tap interfaces inside a QEMU VM.

    Start an iPerf connection stream between QEMU and VPP via
    tap v2 interfaces.

    Linux_ns1 -- iperf_client -- tap1 -- VPP-BD -- tap2 --
                              -- iperfServer -- Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestTapQemu, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTapQemu, cls).tearDownClass()

    def setUp(self):
        """ Perform test setup before running QEMU tests.

        1. Create a namespace for the iPerf Server & Client.
        2. Create 2 tap interfaces in VPP & add them to each namespace.
        3. Add the tap interfaces to a bridge-domain.
        """
        super(TestTapQemu, self).setUp()
        self.client_namespace = 'iprf_client_ns'
        self.server_namespace = 'iprf_server_ns'
        self.client_ip4_prefix = '10.0.0.101/24'
        self.server_ip4_prefix = '10.0.0.102/24'
        create_namespace(self.client_namespace)
        create_namespace(self.server_namespace)
        tap1_if_idx = self.create_tap(101, self.client_namespace,
                                      self.client_ip4_prefix)
        tap2_if_idx = self.create_tap(102, self.server_namespace,
                                      self.server_ip4_prefix)
        self.l2_connect_interfaces(tap1_if_idx, tap2_if_idx)
        # For debugging
        print('VPP tap interfaces:', self.dump_vpp_tap_interfaces())

    def create_tap(self, id, host_namespace, host_ip4_prefix):
        result = self.vapi.api(self.vapi.papi.tap_create_v2,
                                {
                                    'id': id,
                                    'use_random_mac': True,
                                    'host_namespace_set': True,
                                    'host_namespace': host_namespace,
                                    'host_if_name_set': False,
                                    'host_bridge_set': False,
                                    'host_mac_addr_set': False,
                                    'host_ip4_prefix': ip_interface(host_ip4_prefix),
                                    'host_ip4_prefix_set': True
                                    })
        sw_if_index = result.sw_if_index
        self.vapi.api(self.vapi.papi.sw_interface_set_flags,
                       {
                           'sw_if_index': sw_if_index,
                           'flags': 1
                       })
        return sw_if_index

    def dump_vpp_tap_interfaces(self):
        return self.vapi.api(self.vapi.papi.sw_interface_tap_v2_dump, {})

    def l2_connect_interfaces(self, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.api(self.vapi.papi.sw_interface_set_l2_bridge,
                        {
                            'rx_sw_if_index': if_idx,
                            'bd_id': 1,
                            'shg': 0,
                            'port_type': 0,
                            'enable': True
                        })

    def test_tap_iperf(self):
        """ Start an iperf connection stream between QEMU & VPP via tap. """
        iperf = VppIperf()
        iperf.client_ns = self.client_namespace
        iperf.server_ns = self.server_namespace
        iperf.server_ip = str(ip_interface(self.server_ip4_prefix).ip)
        iperf.start()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
