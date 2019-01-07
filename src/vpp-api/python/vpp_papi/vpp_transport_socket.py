#
# VPP Unix Domain Socket Transport.
#
import socket
import struct
import threading
import select
import multiprocessing
try:
    import queue as queue
except ImportError:
    import Queue as queue
import logging


class VppTransportSocketIOError(IOError):
    pass


class VppTransport(object):
    VppTransportSocketIOError = VppTransportSocketIOError

    def __init__(self, parent, read_timeout, server_address, library_path):
        self.connected = False
        self.read_timeout = read_timeout if read_timeout > 0 else 1
        self.parent = parent
        self.server_address = server_address
        self.header = struct.Struct('>QII')
        self.message_table = {}
        self.sque = multiprocessing.Queue()
        self.q = multiprocessing.Queue()
        self.message_thread = threading.Thread(target=self.msg_thread_func)

    def msg_thread_func(self):
        while True:
            try:
                rlist, _, _ = select.select([self.socket,
                                             self.sque._reader], [], [])
            except socket.error:
                # Terminate thread
                logging.error('select failed')
                self.q.put(None)
                return

            for r in rlist:
                if r == self.sque._reader:
                    # Terminate
                    self.q.put(None)
                    return

                elif r == self.socket:
                    try:
                        msg = self._read()
                        if not msg:
                            self.q.put(None)
                            return
                    except socket.error:
                        self.q.put(None)
                        return
                    # Put either to local queue or if context == 0
                    # callback queue
                    if self.parent.has_context(msg):
                        self.q.put(msg)
                    else:
                        self.parent.msg_handler_async(msg)
                else:
                    raise VppTransportSocketIOError(
                        2, 'Unknown response from select')

    def connect(self, name, pfx, msg_handler, rx_qlen):

        # Create a UDS socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.socket.settimeout(self.read_timeout)

        # Connect the socket to the port where the server is listening
        try:
            self.socket.connect(self.server_address)
        except socket.error as msg:
            logging.error("{} on socket {}".format(msg, self.server_address))
            raise

        self.connected = True
        # Initialise sockclnt_create
        sockclnt_create = self.parent.messages['sockclnt_create']
        sockclnt_create_reply = self.parent.messages['sockclnt_create_reply']

        args = {'_vl_msg_id': 15,
                'name': name,
                'context': 124}
        b = sockclnt_create.pack(args)
        self.write(b)
        msg = self._read()
        hdr, length = self.parent.header.unpack(msg, 0)
        if hdr.msgid != 16:
            raise VppTransportSocketIOError('Invalid reply message')

        r, length = sockclnt_create_reply.unpack(msg)
        self.socket_index = r.index
        for m in r.message_table:
            n = m.name.rstrip(b'\x00\x13')
            self.message_table[n] = m.index

        self.message_thread.daemon = True
        self.message_thread.start()

        return 0

    def disconnect(self):
        rv = 0
        try:  # Might fail, if VPP closes socket before packet makes it out
            rv = self.parent.api.sockclnt_delete(index=self.socket_index)
        except IOError:
            pass
        self.connected = False
        self.socket.close()
        self.sque.put(True)  # Terminate listening thread
        self.message_thread.join()
        return rv

    def suspend(self):
        pass

    def resume(self):
        pass

    def callback(self):
        raise NotImplementedError

    def get_callback(self, do_async):
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
            raise VppTransportSocketIOError(1, 'Not connected')

        # Send header
        header = self.header.pack(0, len(buf), 0)
        n = self.socket.send(header)
        n = self.socket.send(buf)

    def _read(self):
        # Header and message
        try:
            msg = self.socket.recv(4096)
            if len(msg) == 0:
                return None
        except socket.error as message:
            logging.error(message)
            raise

        (_, l, _) = self.header.unpack(msg[:16])

        if l > len(msg):
            buf = bytearray(l + 16)
            view = memoryview(buf)
            view[:4096] = msg
            view = view[4096:]
            # Read rest of message
            remaining_bytes = l - 4096 + 16
            while remaining_bytes > 0:
                bytes_to_read = (remaining_bytes if remaining_bytes
                                 <= 4096 else 4096)
                nbytes = self.socket.recv_into(view, bytes_to_read)
                if nbytes == 0:
                    logging.error('recv failed')
                    break
                view = view[nbytes:]
                remaining_bytes -= nbytes
        else:
            buf = msg
        return buf[16:]

    def read(self):
        if not self.connected:
            raise VppTransportSocketIOError(1, 'Not connected')
        try:
            return self.q.get(True, self.read_timeout)
        except queue.Empty:
            return None
