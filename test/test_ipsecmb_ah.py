from test_ipsec_ah import TemplateIpsecAh
from template_ipsec import IpsecTraTests, IpsecTunTests, IpsecTcpTests


class TestIpsecMBAh1(TemplateIpsecAh, IpsecTraTests, IpsecTunTests):
    """ IpsecMB AH - TUN & TRA tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]


class TestIpsecMBAh2(TemplateIpsecAh, IpsecTcpTests):
    """ IpsecMB AH - TCP tests """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]
