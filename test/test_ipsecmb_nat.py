#!/usr/bin/env python

from test_ipsec_nat import TemplateIPSecNAT


class IPSecMBNATTestCase(TemplateIPSecNAT):
    """ IPSecMB/NAT """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    @classmethod
    def ipsec_select_backend(cls):
        cls.vapi.ipsec_select_backend(protocol=cls.vpp_ah_protocol, index=1)
