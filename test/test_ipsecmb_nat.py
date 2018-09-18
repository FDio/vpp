#!/usr/bin/env python

from test_ipsec_nat import TemplateIPSecNAT


class IPSecMBNATTestCase(TemplateIPSecNAT):
    """ IPSecMB/NAT """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]
