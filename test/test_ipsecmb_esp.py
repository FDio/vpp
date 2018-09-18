from test_ipsec_esp import TemplateIpsecEsp
from template_ipsec import IpsecTraTests, IpsecTunTests, IpsecTcpTests


class TestIpsecMBEsp1(TemplateIpsecEsp, IpsecTraTests, IpsecTunTests):
    """ IpsecMB ESP - TUN & TRA tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]


class TestIpsecMBEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ IpsecMB ESP - TCP tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]
