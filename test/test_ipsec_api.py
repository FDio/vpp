import unittest

from framework import VppTestCase, VppTestRunner
from template_ipsec import TemplateIpsec


class IpsecApiTestCase(VppTestCase):
    """ IPSec API tests """

    @classmethod
    def setUpClass(cls):
        super(IpsecApiTestCase, cls).setUpClass()
        cls.create_pg_interfaces([0])
        cls.pg0.config_ip4()
        cls.pg0.admin_up()

    def test_backend_dump(self):
        """ backend dump """
        d = self.vapi.ipsec_backend_dump()
        self.assert_equal(len(d), 2, "number of ipsec backends in dump")
        self.assert_equal(d[0].protocol, TemplateIpsec.vpp_ah_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[0].index, 0, "index in dump entry")
        self.assert_equal(d[0].active, 1, "active flag in dump entry")
        self.assert_equal(d[1].protocol, TemplateIpsec.vpp_esp_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[1].index, 0, "index in dump entry")
        self.assert_equal(d[1].active, 1, "active flag in dump entry")

    def test_select_valid_backend(self):
        """ select valid backend """
        self.vapi.ipsec_select_backend(TemplateIpsec.vpp_ah_protocol, 0)
        self.vapi.ipsec_select_backend(TemplateIpsec.vpp_esp_protocol, 0)

    def test_select_invalid_backend(self):
        """ select invalid backend """
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(TemplateIpsec.vpp_ah_protocol, 200)
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(TemplateIpsec.vpp_esp_protocol, 200)

    def test_select_backend_in_use(self):
        """ attempt to change backend while sad configured """
        params = TemplateIpsec.ipv4_params
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key

        self.vapi.ipsec_sad_add_del_entry(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          TemplateIpsec.vpp_ah_protocol,
                                          self.pg0.local_addr_n[addr_type],
                                          self.pg0.remote_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6)
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(
                protocol=TemplateIpsec.vpp_ah_protocol, index=0)

        self.vapi.ipsec_sad_add_del_entry(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          TemplateIpsec.vpp_ah_protocol,
                                          self.pg0.local_addr_n[addr_type],
                                          self.pg0.remote_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_select_backend(
            protocol=TemplateIpsec.vpp_ah_protocol, index=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
