#!/usr/bin/env python
import unittest
from framework import is_platform_aarch64
from test_ipsec_nat import TemplateIPSecNAT


@unittest.skipIf(is_platform_aarch64, "Intel ipsec MB not available on ARM")
class IPSecMBNATTestCase(TemplateIPSecNAT):
    """ IPSecMB/NAT """
    extra_vpp_plugin_config = [
        "plugin", "ipsecmb_plugin.so", "{", "enable", "}"]

    def ipsec_select_backend(self):
        self.vapi.ipsec_select_backend(protocol=self.vpp_ah_protocol, index=1)
