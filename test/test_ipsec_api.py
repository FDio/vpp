import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from template_ipsec import IPsecIPv4Params
from vpp_papi import VppEnum
from ipaddress import IPv4Address

from vpp_ipsec import VppIpsecSA


class IpsecApiTestCase(VppTestCase):
    """IPSec API tests"""

    vpp_worker_count = 2

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

        self.vpp_esp_protocol = VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP
        self.vpp_ah_protocol = VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_AH
        self.ipv4_params = IPsecIPv4Params()

    def tearDown(self):
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(IpsecApiTestCase, self).tearDown()

    def test_backend_dump(self):
        """backend dump"""
        d = self.vapi.ipsec_backend_dump()
        self.assert_equal(len(d), 2, "number of ipsec backends in dump")
        self.assert_equal(
            d[0].protocol, self.vpp_ah_protocol, "ipsec protocol in dump entry"
        )
        self.assert_equal(d[0].index, 0, "index in dump entry")
        self.assert_equal(d[0].active, 1, "active flag in dump entry")
        self.assert_equal(
            d[1].protocol, self.vpp_esp_protocol, "ipsec protocol in dump entry"
        )
        self.assert_equal(d[1].index, 0, "index in dump entry")
        self.assert_equal(d[1].active, 1, "active flag in dump entry")

    def test_select_valid_backend(self):
        """select valid backend"""
        self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 0)
        self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 0)

    def test_select_invalid_backend(self):
        """select invalid backend"""
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 200)
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 200)

    def test_select_backend_in_use(self):
        """attempt to change backend while sad configured"""
        params = self.ipv4_params
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key

        self.vapi.ipsec_sad_entry_add_del(
            is_add=1,
            entry={
                "sad_id": scapy_tun_sa_id,
                "spi": scapy_tun_spi,
                "integrity_algorithm": auth_algo_vpp_id,
                "integrity_key": {
                    "data": auth_key,
                    "length": len(auth_key),
                },
                "crypto_algorithm": crypt_algo_vpp_id,
                "crypto_key": {
                    "data": crypt_key,
                    "length": len(crypt_key),
                },
                "protocol": self.vpp_ah_protocol,
                "tunnel_src": self.pg0.local_addr[addr_type],
                "tunnel_dst": self.pg0.remote_addr[addr_type],
            },
        )
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(protocol=self.vpp_ah_protocol, index=0)

        self.vapi.ipsec_sad_entry_add_del(
            is_add=0,
            entry={
                "sad_id": scapy_tun_sa_id,
                "spi": scapy_tun_spi,
                "integrity_algorithm": auth_algo_vpp_id,
                "integrity_key": {
                    "data": auth_key,
                    "length": len(auth_key),
                },
                "crypto_algorithm": crypt_algo_vpp_id,
                "crypto_key": {
                    "data": crypt_key,
                    "length": len(crypt_key),
                },
                "protocol": self.vpp_ah_protocol,
                "tunnel_src": self.pg0.local_addr[addr_type],
                "tunnel_dst": self.pg0.remote_addr[addr_type],
            },
        )
        self.vapi.ipsec_select_backend(protocol=self.vpp_ah_protocol, index=0)

    def __sa_dump(self, sa):
        sa_dumps = self.vapi.ipsec_sa_v5_dump()
        for dump in sa_dumps:
            if dump.entry.sad_id == sa.id:
                return dump
        self.fail("SA not found in VPP")

    def test_sa_basic(self):
        """basic SA API tests"""
        sa = VppIpsecSA(
            self,
            self.ipv4_params.scapy_tun_sa_id,
            self.ipv4_params.scapy_tun_spi,
            self.ipv4_params.auth_algo_vpp_id,
            self.ipv4_params.auth_key,
            self.ipv4_params.crypt_algo_vpp_id,
            self.ipv4_params.crypt_key,
            VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
            flags=VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY
            | VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_IS_INBOUND,
        )
        sa.add_vpp_config()

        # check general SA dump
        dump = self.__sa_dump(sa)
        self.assertEqual(dump.entry.sad_id, sa.id)
        self.assertEqual(dump.entry.spi, sa.spi)
        self.assertEqual(dump.entry.protocol, sa.proto)
        self.assertEqual(dump.entry.crypto_algorithm, sa.crypto_alg)
        self.assertEqual(
            dump.entry.crypto_key.data[: dump.entry.crypto_key.length], sa.crypto_key
        )
        self.assertEqual(dump.entry.integrity_algorithm, sa.integ_alg)
        self.assertEqual(
            dump.entry.integrity_key.data[: dump.entry.integrity_key.length],
            sa.integ_key,
        )
        self.assertEqual(dump.entry.flags, sa.flags)
        self.assertEqual(dump.entry.tunnel.instance, 0)
        self.assertEqual(dump.entry.tunnel.src, IPv4Address("0.0.0.0"))
        self.assertEqual(dump.entry.tunnel.dst, IPv4Address("0.0.0.0"))
        self.assertEqual(dump.entry.tunnel.sw_if_index, 0)
        self.assertEqual(dump.entry.tunnel.table_id, sa.table_id)
        self.assertEqual(dump.entry.tunnel.encap_decap_flags, sa.tun_flags)
        self.assertEqual(dump.entry.tunnel.mode, 0)
        self.assertEqual(dump.entry.tunnel.flags, 0)
        self.assertEqual(dump.entry.tunnel.dscp, 0)
        self.assertEqual(dump.entry.tunnel.hop_limit, 0)
        self.assertEqual(dump.entry.salt, 0)
        self.assertEqual(dump.entry.udp_src_port, 0)
        self.assertEqual(dump.entry.udp_dst_port, 0)
        self.assertEqual(dump.entry.anti_replay_window_size, 64)
        self.assertEqual(dump.sw_if_index, 0xFFFFFFFF)
        self.assertEqual(dump.seq_outbound, 0)
        self.assertEqual(dump.last_seq_inbound, 0)
        self.assertEqual(dump.replay_window, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(dump.thread_index, 0xFFFF)
        self.assertEqual(dump.stat_index, 0)

        # check SA binding API
        self.vapi.ipsec_sad_bind(sa_id=sa.id, worker=1)
        dump = self.__sa_dump(sa)
        self.assertEqual(dump.thread_index, 2)

        sa.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
