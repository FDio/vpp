from test_ipsec_esp import TemplateIpsecEsp
from template_ipsec import IpsecTraTests, IpsecTunTests, IpsecTcpTests


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

    @classmethod
    def ipsec_select_backend(cls):
        cls.vapi.ipsec_select_backend(protocol=cls.vpp_esp_protocol, index=1)


class TestIpsecMBEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ IpsecMB ESP - TCP tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    @classmethod
    def ipsec_select_backend(cls):
        cls.vapi.ipsec_select_backend(protocol=cls.vpp_esp_protocol, index=1)
