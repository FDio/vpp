from vpp_object import VppObject


class VppDHCPProxy(VppObject):

    def __init__(
        self,
        test,
        dhcp_server,
        dhcp_src_address,
        rx_vrf_id=0,
        server_vrf_id=0,
    ):
        self._test = test
        self._rx_vrf_id = rx_vrf_id
        self._server_vrf_id = server_vrf_id
        self._dhcp_server = dhcp_server
        self._dhcp_src_address = dhcp_src_address

    def set_proxy(
            self,
            dhcp_server,
            dhcp_src_address,
            rx_vrf_id=0,
            server_vrf_id=0):
        if self.query_vpp_config():
            raise Exception('Vpp config present')
        self._rx_vrf_id = rx_vrf_id
        self._server_vrf_id = server_vrf_id
        self._dhcp_server = dhcp_server
        self._dhcp_src_address = dhcp_src_address

    def add_vpp_config(self):
        self._test.vapi.dhcp_proxy_config(
            rx_vrf_id=self._rx_vrf_id,
            server_vrf_id=self._server_vrf_id,
            dhcp_server=self._dhcp_server,
            dhcp_src_address=self._dhcp_src_address)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.dhcp_proxy_config(
            rx_vrf_id=self._rx_vrf_id,
            server_vrf_id=self._server_vrf_id,
            dhcp_server=self._dhcp_server,
            dhcp_src_address=self._dhcp_src_address,
            is_add=0)

    def get_vpp_dump(self):
        dump = self._test.vapi.dhcp_proxy_dump()
        for entry in dump:
            if entry.rx_vrf_id == self._rx_vrf_id:
                return entry

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return True if dump else False

    def object_id(self):
        return "dhcp-proxy-%d" % self._rx_vrf_id


class VppDHCPClient(VppObject):

    def __init__(
            self,
            test,
            sw_if_index,
            hostname,
            id=None,
            want_dhcp_event=False,
            set_broadcast_flag=True,
            dscp=None,
            pid=None):
        self._test = test
        self._sw_if_index = sw_if_index
        self._hostname = hostname
        self._id = id
        self._want_dhcp_event = want_dhcp_event
        self._set_broadcast_flag = set_broadcast_flag
        self._dscp = dscp
        self._pid = pid

    def set_client(
            self,
            sw_if_index,
            hostname,
            id=None,
            want_dhcp_event=False,
            set_broadcast_flag=True,
            dscp=None,
            pid=None):
        if self.query_vpp_config():
            raise Exception('Vpp config present')
        self._sw_if_index = sw_if_index
        self._hostname = hostname
        self._id = id
        self._want_dhcp_event = want_dhcp_event
        self._set_broadcast_flag = set_broadcast_flag
        self._dscp = dscp
        self._pid = pid

    def add_vpp_config(self):
        client = {'sw_if_index': self._sw_if_index, 'hostname': self._hostname,
                  'id': self._id, 'want_dhcp_event': self._want_dhcp_event,
                  'set_broadcast_flag': self._set_broadcast_flag,
                  'dscp': self._dscp, 'pid': self._pid}
        self._test.vapi.dhcp_client_config(client=client)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        client = client = {
            'sw_if_index': self._sw_if_index,
            'hostname': self._hostname}
        self._test.vapi.dhcp_client_config(client=client, is_add=0)

    def get_vpp_dump(self):
        dump = self._test.vapi.dhcp_client_dump()
        for entry in dump:
            if entry.client.sw_if_index == self._sw_if_index:
                return entry

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return True if dump else False

    def object_id(self):
        return "dhcp-client-%s/%d" % (self._hostname, self._sw_if_index)
