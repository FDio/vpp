#
# VPP Unix Domain Socket Transport.
#
import socket
import struct


class VppTransport:
    def __init__(self, parent, read_timeout, server_address):
        self.connected = False
        self.read_timeout = read_timeout if read_timeout > 0 else 1
        self.parent = parent
        self.server_address = server_address
        self.header = struct.Struct('>QII')
        self.message_table = {}

    def connect(self, name, pfx, msg_handler, rx_qlen):

        # Create a UDS socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.socket.settimeout(self.read_timeout)

        # Connect the socket to the port where the server is listening
        print('connecting to: %s' % self.server_address)
        try:
            self.socket.connect(self.server_address)
        except socket.error as msg:
            print(msg)
            import sys
            sys.exit(1)

        self.connected = True

        # Initialise sockclnt_create
        sockclnt_create = self.parent.messages['sockclnt_create']
        sockclnt_create_reply = self.parent.messages['sockclnt_create_reply']

        args = {'_vl_msg_id': 15,
                'name': name,
                'context': 124}
        b = sockclnt_create.pack(args)
        self.write(b)
        msg = self.read()
        i, ci = self.parent.header.unpack(msg, 0)
        if i != 16:
            raise IOError('Invalid reply message')

        r = sockclnt_create_reply.unpack(msg)
        self.socket_index = r.index

        for m in r.message_table:
            n = m.name.rstrip(b'\x00')
            self.message_table[n] = m.index
        return 0

    def disconnect(self):
        rv = self.parent.api.sockclnt_delete(index=self.socket_index)
        self.connected = False
        self.socket.close()

    def suspend(self):
        pass

    def resume(self):
        pass

    def callback(self):
        print('Callback function called')

    def get_callback(self, async):
        return self.callback

    def get_msg_index(self, name):
        try:
            return self.message_table[name]
        except KeyError:
            return 0

    def msg_table_max_index(self):
        return len(self.message_table)

    def write(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise IOError(1, 'Not connected')

        # Send header
        header = self.header.pack(0, len(buf), 0)
        n = self.socket.send(header)
        n = self.socket.send(buf)

    def read(self):
        if not self.connected:
            raise IOError(1, 'Not connected')

        # Header and message
        # TODO: Read first header, then message?
        msg = self.socket.recv(250000)
        if len(msg) == 0:
            raise
        (_, l, _) = self.header.unpack(msg[:16])
        return msg[16:]
