import enum
import socket

from vpp_object import VppObject


class MEMIF_ROLE(enum.IntEnum):  # noqa
    MASTER = 0
    SLAVE = 1


class MEMIF_MODE(enum.IntEnum):  # noqa
    ETHERNET = 0
    IP = 1
    PUNT_INJECT = 2


def get_if_dump(dump, sw_if_index):
    for d in dump:
        if (d.sw_if_index == sw_if_index):
            return d


def query_all_memif_vpp_config(_test):
    return _test.vapi.memif_dump()


def remove_all_memif_vpp_config(_test):
    dump = _test.vapi.memif_dump()
    for d in dump:
        _test.vapi.memif_delete(d.sw_if_index)
    dump = _test.vapi.memif_socket_filename_dump()
    for d in dump:
        if d.socket_id != 0:
            _test.vapi.memif_socket_filename_add_del(
                0, d.socket_id, d.socket_filename)


class VppSocketFilename(VppObject):
    def __init__(self, test, socket_id, socket_filename,
                 add_default_folder=False):
        self._test = test
        self.socket_id = socket_id
        self.socket_filename = socket_filename

        # if True insert default socket folder before socket filename,
        # after adding vpp config
        self.add_default_folder = add_default_folder

    def add_vpp_config(self):
        rv = self._test.vapi.memif_socket_filename_add_del(
            1, self.socket_id, self.socket_filename)
        if self.add_default_folder:
            self.socket_filename = self._test.tempdir + "/" \
                                   + self.socket_filename
        return rv

    def remove_vpp_config(self):
        return self._test.vapi.memif_socket_filename_add_del(
            0, self.socket_id, self.socket_filename)

    def query_vpp_config(self):
        return self._test.vapi.memif_socket_filename_dump()

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "%d" % (self.socket_id)


class VppMemif(VppObject):
    def __init__(self, test, role, mode, rx_queues=0, tx_queues=0, if_id=0,
                 socket_id=0, secret="", ring_size=0, buffer_size=0,
                 hw_addr=""):
        self._test = test
        self.role = role
        self.mode = mode
        self.rx_queues = rx_queues
        self.tx_queues = tx_queues
        self.if_id = if_id
        self.socket_id = socket_id
        self.secret = secret
        self.ring_size = ring_size
        self.buffer_size = buffer_size
        self.hw_addr = hw_addr
        self.sw_if_index = None
        self.ip4_addr = "192.168.%d.%d" % (self.if_id + 1, self.role + 1)
        self.ip4_addr_len = 24

    def add_vpp_config(self):
        rv = self._test.vapi.memif_create(self.role, self.mode, self.rx_queues,
                                          self.tx_queues, self.if_id,
                                          self.socket_id, self.secret,
                                          self.ring_size, self.buffer_size,
                                          self.hw_addr)
        self.sw_if_index = rv.sw_if_index
        return self.sw_if_index

    def admin_up(self):
        if self.sw_if_index:
            return self._test.vapi.sw_interface_set_flags(self.sw_if_index, 1)

    def admin_down(self):
        if self.sw_if_index:
            return self._test.vapi.sw_interface_set_flags(self.sw_if_index, 0)

    def wait_for_link_up(self, timeout, step=1):
        if not self.sw_if_index:
            return False
        while True:
            dump = self.query_vpp_config()
            if dump.link_up_down == 1:
                return True
            self._test.sleep(step)
            timeout -= step
            if timeout <= 0:
                return False

    def config_ip4(self):
        return self._test.vapi.sw_interface_add_del_address(
            self.sw_if_index, socket.inet_pton(
                socket.AF_INET, self.ip4_addr), self.ip4_addr_len)

    def remove_vpp_config(self):
        self._test.vapi.memif_delete(self.sw_if_index)
        self.sw_if_index = None

    def query_vpp_config(self):
        if not self.sw_if_index:
            return None
        dump = self._test.vapi.memif_dump()
        return get_if_dump(dump, self.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        if self.sw_if_index:
            return "%d:%d:%d" % (self.role, self.if_id, self.sw_if_index)
        else:
            return "%d:%d:None" % (self.role, self.if_id)
