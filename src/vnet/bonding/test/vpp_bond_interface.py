from vpp_interface import VppInterface


class VppBondInterface(VppInterface):
    """VPP bond interface."""

    def __init__(self, test, mode, lb=None, numa_only=None,
                 use_custom_mac=None, mac_address='', interface_id=0xffffffff):

        """ Create VPP Bond interface """
        super(VppBondInterface, self).__init__(test)
        self.mode = mode
        self.lb = lb
        self.numa_only = numa_only
        self.enable_gso = enable_gso
        self.use_custom_mac = use_custom_mac
        self.mac_address = mac_address
        self.interface_id = interface_id

    def encode(self):
        return {'mode': self.mode,
                'lb': self.lb,
                'numa_only': self.numa_only,
                'use_custom_mac': self.use_custom_mac,
                'mac_address': self.mac_address,
                'id': self.interface_id
                }

    def add_vpp_config(self):
        r = self.test.vapi.bond_create2(**self.encode())
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.bond_delete(sw_if_index=self.sw_if_index)

    def add_member_vpp_bond_interface(self,
                                      sw_if_index,
                                      is_passive=0,
                                      is_long_timeout=0):
        self.test.vapi.bond_add_member(sw_if_index,
                                       self.sw_if_index,
                                       is_passive,
                                       is_long_timeout)

    def is_interface_config_in_dump(self, dump):
        for i in dump:
            if i.sw_if_index == self.sw_if_index:
                return True

        return False

    def enslave_vpp_bond_interface(self,
                                   sw_if_index,
                                   is_passive=None,
                                   is_long_timeout=None):
        self.test.vapi.bond_enslave(sw_if_index=sw_if_index,
                                    bond_sw_if_index=self.sw_if_index,
                                    is_passive=is_passive,
                                    is_long_timeout=is_long_timeout)

    def detach_vpp_bond_interface(self,
                                  sw_if_index):
        self.test.vapi.bond_detach_slave(sw_if_index=sw_if_index)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._test}, {self.mode}, " \
               f"lb={repr(self.lb)}, numa_only={repr(self.numa_only)}," \
               f"use_custom_mac={repr(self.use_custom_mac)}, " \
               f"mac_address={repr(self.mac_address)}, " \
               f"interface_id={repr(self.interface_id)})"
