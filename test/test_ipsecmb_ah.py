from test_ipsec_ah import TemplateIpsecAh
from template_ipsec import IpsecTraTests, IpsecTunTests, IpsecTcpTests


class TestIpsecMBAh1(TemplateIpsecAh, IpsecTraTests, IpsecTunTests):
    """ IpsecMB AH - TUN & TRA tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    tra4_encrypt_node_name = "ah4-encrypt-ipsecmb"
    tra4_decrypt_node_name = "ah4-decrypt-ipsecmb"
    tra6_encrypt_node_name = "ah6-encrypt-ipsecmb"
    tra6_decrypt_node_name = "ah6-decrypt-ipsecmb"
    tun4_encrypt_node_name = "ah4-encrypt-ipsecmb"
    tun4_decrypt_node_name = "ah4-decrypt-ipsecmb"
    tun6_encrypt_node_name = "ah6-encrypt-ipsecmb"
    tun6_decrypt_node_name = "ah6-decrypt-ipsecmb"

    @classmethod
    def ipsec_select_backend(cls):
        cls.vapi.ipsec_select_backend(protocol=cls.vpp_ah_protocol, index=1)


class TestIpsecMBAh2(TemplateIpsecAh, IpsecTcpTests):
    """ IpsecMB AH - TCP tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    @classmethod
    def ipsec_select_backend(cls):
        cls.vapi.ipsec_select_backend(protocol=cls.vpp_ah_protocol, index=1)
