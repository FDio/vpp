from vpp_interface import VppInterface


class VppVhostInterface(VppInterface):
    """VPP vhost interface."""

    def __init__(
        self,
        test,
        sock_filename,
        is_server=0,
        renumber=0,
        disable_mrg_rxbuf=0,
        disable_indirect_desc=0,
        enable_gso=0,
        enable_packed_ring=0,
        enable_event_idx=0,
        custom_dev_instance=0xFFFFFFFF,
        use_custom_mac=0,
        mac_address="",
        tag="",
    ):

        """Create VPP Vhost interface"""
        super(VppVhostInterface, self).__init__(test)
        self.is_server = is_server
        self.sock_filename = sock_filename
        self.renumber = renumber
        self.disable_mrg_rxbuf = disable_mrg_rxbuf
        self.disable_indirect_desc = disable_indirect_desc
        self.enable_gso = enable_gso
        self.enable_packed_ring = enable_packed_ring
        self.enable_event_idx = enable_event_idx
        self.custom_dev_instance = custom_dev_instance
        self.use_custom_mac = use_custom_mac
        self.mac_address = mac_address
        self.tag = tag

    def add_vpp_config(self):
        r = self.test.vapi.create_vhost_user_if_v2(
            self.is_server,
            self.sock_filename,
            self.renumber,
            self.disable_mrg_rxbuf,
            self.disable_indirect_desc,
            self.enable_gso,
            self.enable_packed_ring,
            self.enable_event_idx,
            self.custom_dev_instance,
            self.use_custom_mac,
            self.mac_address,
            self.tag,
        )
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.delete_vhost_user_if(self.sw_if_index)

    def is_interface_config_in_dump(self, dump):
        for i in dump:
            if i.sw_if_index == self.sw_if_index:
                return True
        else:
            return False
