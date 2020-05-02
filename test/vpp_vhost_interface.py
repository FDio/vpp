from vpp_interface import VppInterface


class VppVhostInterface(VppInterface):
    """VPP vhost interface."""
    details_api = 'sw_interface_vhost_user_dump'

    def __init__(self, test, sock_filename, is_server=None, renumber=None,
                 disable_mrg_rxbuf=None, disable_indirect_desc=None, gso=None,
                 packed_ring=None, custom_dev_instance=None,
                 use_custom_mac=None,
                 mac_address='', tag=''):

        """ Create VPP Vhost interface """
        super(VppVhostInterface, self).__init__(test)
        self.is_server = is_server
        self.sock_filename = sock_filename
        self.renumber = renumber
        self.disable_mrg_rxbuf = disable_mrg_rxbuf
        self.disable_indirect_desc = disable_indirect_desc
        self.gso = gso
        self.packed_ring = packed_ring
        self.custom_dev_instance = custom_dev_instance
        self.use_custom_mac = use_custom_mac
        self.mac_address = mac_address
        self.tag = tag

    def add_vpp_config(self):
        r = self.test.vapi.create_vhost_user_if(
            is_server=self.is_server,
            sock_filename=self.sock_filename,
            renumber=self.renumber,
            disable_mrg_rxbuf=self.disable_mrg_rxbuf,
            disable_indirect_desc=self.disable_indirect_desc,
            enable_gso=self.gso,
            enable_packed=self.packed_ring,
            custom_dev_instance=self.custom_dev_instance,
            use_custom_mac=self.use_custom_mac,
            mac_address=self.mac_address,
            tag=self.tag)
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.delete_vhost_user_if(
            sw_if_index=self.sw_if_index)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._test}, " \
               f"{self.sock_filename}, is_server={repr(self.is_server)}, " \
               f"renumber={repr(self.renumber)}," \
               f"disable_mrg_rxbuf={repr(self.disable_mrg_rxbuf)}, " \
               f"disable_indirect_desc={repr(self.disable_indirect_desc)}, " \
               f"gso={repr(self.gso)}, " \
               f"packed_ring={repr(self.packed_ring)}, " \
               f"custom_dev_instance={repr(self.custom_dev_instance)}," \
               f"use_custom_mac={repr(self.use_custom_mac)}," \
               f"mac_address={repr(self.mac_address)}, tag={repr(self.tag)})"
