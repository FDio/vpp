
from vpp_interface import VppInterface
import socket
from util import mactobinary


class VppPppoeInterface(VppInterface):
    """
    VPP Pppoe interface
    """

    def __init__(self, test, client_ip, client_mac,
                 session_id, decap_vrf_id=0):
        """ Create VPP PPPoE4 interface """
        self._test = test
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.session_id = session_id
        self.decap_vrf_id = decap_vrf_id

    def add_vpp_config(self):
        cip = socket.inet_pton(socket.AF_INET, self.client_ip)
        cmac = mactobinary(self.client_mac)
        r = self.test.vapi.pppoe_add_del_session(
                cip, cmac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id)
        self._sw_if_index = r.sw_if_index
        super(VppPppoeInterface, self).__init__(self._test)
        self.generate_remote_hosts()

    def remove_vpp_config(self):
        cip = socket.inet_pton(socket.AF_INET, self.client_ip)
        cmac = mactobinary(self.client_mac)
        self.unconfig()
        r = self.test.vapi.pppoe_add_del_session(
                cip, cmac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id,
                is_add=0)
