"""
  MAC Types

"""

from util import mactobinary


class VppMacAddress():
    def __init__(self, addr):
        self.address = addr

    def encode(self):
        return {
            'bytes': self.bytes
        }

    @property
    def bytes(self):
        return mactobinary(self.address)

    @property
    def address(self):
        return self.address

    @address.setter
    def address(self, value):
        self.address = value

    def __str__(self):
        return self.address

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.address == other.address
        elif hasattr(other, "bytes"):
            # vl_api_mac_addres_t
            return self.bytes == other.bytes
        else:
            raise TypeError("Comparing VppMacAddress:%s"
                            "with unknown type: %s" %
                            (self, other))
        return False
