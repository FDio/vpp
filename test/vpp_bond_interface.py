from vpp_object import VppObject
from vpp_interface import VppInterface


class VppBondInterface(VppInterface):
    """VPP bond interface."""

    def __init__(
        self,
        test,
        mode,
        lb=0,
        numa_only=0,
        enable_gso=0,
        use_custom_mac=0,
        mac_address="",
        id=0xFFFFFFFF,
    ):

        """Create VPP Bond interface"""
        super(VppBondInterface, self).__init__(test)
        self.mode = mode
        self.lb = lb
        self.numa_only = numa_only
        self.enable_gso = enable_gso
        self.use_custom_mac = use_custom_mac
        self.mac_address = mac_address
        self.id = id

    def add_vpp_config(self):
        r = self.test.vapi.bond_create2(
            self.mode,
            self.lb,
            self.numa_only,
            self.enable_gso,
            self.use_custom_mac,
            self.mac_address,
            self.id,
        )
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.bond_delete(self.sw_if_index)

    def add_member_vpp_bond_interface(
        self, sw_if_index, is_passive=0, is_long_timeout=0
    ):
        self.test.vapi.bond_add_member(
            sw_if_index, self.sw_if_index, is_passive, is_long_timeout
        )

    def detach_vpp_bond_interface(self, sw_if_index):
        self.test.vapi.bond_detach_member(sw_if_index)

    def is_interface_config_in_dump(self, dump):
        for i in dump:
            if i.sw_if_index == self.sw_if_index:
                return True
        else:
            return False
