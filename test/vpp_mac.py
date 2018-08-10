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
        return self.addr.address
