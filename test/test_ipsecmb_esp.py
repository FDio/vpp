import unittest
from framework import is_platform_aarch64
from test_ipsec_esp import TemplateIpsecEsp
from template_ipsec import IpsecTraTests, IpsecTunTests, IpsecTcpTests


@unittest.skipIf(is_platform_aarch64, "Intel ipsec MB not available on ARM")
class TestIpsecMBEsp1(TemplateIpsecEsp, IpsecTraTests, IpsecTunTests):
    """ IpsecMB ESP - TUN & TRA tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]
    tra4_encrypt_node_name = "esp4-encrypt-ipsecmb"
    tra4_decrypt_node_name = "esp4-decrypt-ipsecmb"
    tra6_encrypt_node_name = "esp6-encrypt-ipsecmb"
    tra6_decrypt_node_name = "esp6-decrypt-ipsecmb"
    tun4_encrypt_node_name = "esp4-encrypt-ipsecmb"
    tun4_decrypt_node_name = "esp4-decrypt-ipsecmb"
    tun6_encrypt_node_name = "esp6-encrypt-ipsecmb"
    tun6_decrypt_node_name = "esp6-decrypt-ipsecmb"

    def ipsec_select_backend(self):
        self.vapi.ipsec_select_backend(protocol=self.vpp_esp_protocol, index=1)


@unittest.skipIf(is_platform_aarch64, "Intel ipsec MB not available on ARM")
class TestIpsecMBEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ IpsecMB ESP - TCP tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    def ipsec_select_backend(self):
        self.vapi.ipsec_select_backend(protocol=self.vpp_esp_protocol, index=1)
