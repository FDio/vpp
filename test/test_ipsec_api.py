import unittest

from framework import VppTestCase, VppTestRunner
from template_ipsec import TemplateIpsec, IPsecIPv4Params
from vpp_papi import VppEnum


class IpsecApiTestCase(VppTestCase):
    """ IPSec API tests """

    @classmethod
    def setUpClass(cls):
        super(IpsecApiTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IpsecApiTestCase, cls).tearDownClass()

    def setUp(self):
        super(IpsecApiTestCase, self).setUp()
        self.create_pg_interfaces([0])
        self.pg0.config_ip4()
        self.pg0.admin_up()

        self.vpp_esp_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                 IPSEC_API_PROTO_ESP)
        self.vpp_ah_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                IPSEC_API_PROTO_AH)
        self.ipv4_params = IPsecIPv4Params()

    def tearDown(self):
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(IpsecApiTestCase, self).tearDown()

    def test_backend_dump(self):
        """ backend dump """
        d = self.vapi.ipsec_backend_dump()
        self.assert_equal(len(d), 2, "number of ipsec backends in dump")
        self.assert_equal(d[0].protocol, self.vpp_ah_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[0].index, 0, "index in dump entry")
        self.assert_equal(d[0].active, 1, "active flag in dump entry")
        self.assert_equal(d[1].protocol, self.vpp_esp_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[1].index, 0, "index in dump entry")
        self.assert_equal(d[1].active, 1, "active flag in dump entry")

    def test_select_valid_backend(self):
        """ select valid backend """
        self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 0)
        self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 0)

    def test_select_invalid_backend(self):
        """ select invalid backend """
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 200)
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 200)

    def test_select_backend_in_use(self):
        """ attempt to change backend while sad configured """
        params = self.ipv4_params
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key

        self.vapi.ipsec_sad_entry_add_del(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_ah_protocol,
                                          self.pg0.local_addr[addr_type],
                                          self.pg0.remote_addr[addr_type])
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(
                protocol=self.vpp_ah_protocol, index=0)

        self.vapi.ipsec_sad_entry_add_del(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_ah_protocol,
                                          self.pg0.local_addr[addr_type],
                                          self.pg0.remote_addr[addr_type],
                                          is_add=0)
        self.vapi.ipsec_select_backend(
            protocol=self.vpp_ah_protocol, index=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
