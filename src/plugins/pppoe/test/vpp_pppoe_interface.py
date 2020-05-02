
from vpp_interface import VppInterface
import socket
from vpp_papi import mac_pton


class VppPppoeInterface(VppInterface):
    """
    VPP Pppoe interface
    """
    details_api = 'pppoe_session_dump'

    def __init__(self, test, client_ip, client_mac,
                 session_id, decap_vrf_id=None):
        """ Create VPP PPPoE4 interface """
        super(VppPppoeInterface, self).__init__(test)
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.session_id = session_id
        self.decap_vrf_id = decap_vrf_id

    def add_vpp_config(self):
        r = self.test.vapi.pppoe_add_del_session(
                client_ip=self.client_ip,
                client_mac=self.client_mac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id)
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()

    def remove_vpp_config(self):
        self.unconfig()
        self.test.vapi.pppoe_add_del_session(
                client_ip=self.client_ip,
                client_mac=self.client_mac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id,
                is_add=0)
