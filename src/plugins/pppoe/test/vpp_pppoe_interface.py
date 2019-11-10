
import socket

from vpp_papi import mac_pton

from vpp_interface import VppInterface


class VppPppoeInterface(VppInterface):
    """
    VPP Pppoe interface
    """

    def __init__(self, test, client_ip, client_mac,
                 session_id, decap_vrf_id=0):
        """ Create VPP PPPoE4 interface """
        super(VppPppoeInterface, self).__init__(test)
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.session_id = session_id
        self.decap_vrf_id = decap_vrf_id

    def add_vpp_config(self):
        cip = socket.inet_pton(socket.AF_INET, self.client_ip)
        cmac = mac_pton(self.client_mac)
        r = self.test.vapi.pppoe_add_del_session(
                cip, cmac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()

    def remove_vpp_config(self):
        cip = socket.inet_pton(socket.AF_INET, self.client_ip)
        cmac = mac_pton(self.client_mac)
        self.unconfig()
        self.test.vapi.pppoe_add_del_session(
                cip, cmac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id,
                is_add=0)
