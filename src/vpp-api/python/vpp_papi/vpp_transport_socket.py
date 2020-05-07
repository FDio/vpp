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
from . import vpp_papi


class VppTransportSocketIOError(IOError):
    # TODO: Document different values of error number (first numeric argument).
    pass


class VppTransport(object):
    VppTransportSocketIOError = VppTransportSocketIOError

    def __init__(self, parent, read_timeout, server_address):
        self.connected = False
        self.read_timeout = read_timeout if read_timeout > 0 else 1
        self.parent = parent
        self.server_address = server_address
        self.header = struct.Struct('>QII')
        self.message_table = {}
        # These queues can be accessed async.
        # They are always up, but replaced on connect.
        # TODO: Use multiprocessing.Pipe instead of multiprocessing.Queue
        # if possible.
        self.sque = multiprocessing.Queue()
        self.q = multiprocessing.Queue()
        # The following fields are set in connect().
        self.message_thread = None
        self.socket = None
        self.remember_sent = False
        self.last_sent = None

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
                        msg = self.read_message()
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

    def start_reader_thread(self):
        """Create and start thread to read and handle messages on background.

        In high performance asynchronous setups this background handling
        is a bottleneck, so we are allowing users
        to stop and start it as needed.

        If thread appears to be created already, raise an exception.
        """
        if self.message_thread is not None:
            raise VppTransportSocketIOError(
                1, "start_reader_thread: already started"
            )
        self.message_thread = threading.Thread(target=self.msg_thread_func)
        self.message_thread.daemon = True
        self.message_thread.start()


    def stop_reader_thread(self):
        """Stop the thread that reads and handles messages on background.

        In high performance asynchronous setups this background handling
        is a bottleneck, so we are allowing users
        to stop and start it as needed.

        If the thread appears to be stopped already, return early.

        The current implementation fails if there are messages in self.q.
        """
        if self.message_thread is None:
            return
        if self.sque is None:
            raise VppTransportSocketIOError(
                1, "stop_reader_thread: sque is None"
            )
        self.sque.put(True)  # This tells the thread function to return.
        if self.message_thread.is_alive():
            # Join works for threads that stopped already,
            # but not for threads that never started for some reason.
            # Hence the condition is needed, it is not just a speedup.
            self.message_thread.join()
        # Pop the one None added when the thread closes.
        non = self.q.get(block=True, timeout=self.read_timeout)
        if non is not None:
            raise VppTransportSocketIOError(
                1, "Got non-None from q {non!r}".format(non-non)
            )
        # Also pop the True we used to kill the thread with.
        non = self.sque.get(block=False)
        if non is not True:
            raise VppTransportSocketIOError(
                1, "Got non-True from sque {non!r}".format(non=non)
            )
        self.message_thread = None


    def connect(self, name, pfx, msg_handler, rx_qlen):
        # TODO: Reorder the actions and add "roll-backs",
        # to restore clean disconnect state when failure happens durng connect.

        if self.message_thread is not None:
            raise VppTransportSocketIOError(
                1, "PAPI socket transport connect: Need to disconnect first.")

        # Create a UDS socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(self.read_timeout)

        # Connect the socket to the port where the server is listening
        try:
            self.socket.connect(self.server_address)
        except socket.error as msg:
            logging.error("{} on socket {}".format(msg, self.server_address))
            raise

        self.connected = True

        # Queues' feeder threads from previous connect may still be sending.
        # Close and join to avoid any errors.
        self.sque.close()
        self.q.close()
        self.sque.join_thread()
        self.q.join_thread()
        # Finally safe to replace.
        self.sque = multiprocessing.Queue()
        self.q = multiprocessing.Queue()

        # Initialise sockclnt_create
        sockclnt_create = self.parent.messages['sockclnt_create']
        sockclnt_create_reply = self.parent.messages['sockclnt_create_reply']

        args = {'_vl_msg_id': 15,
                'name': name,
                'context': 124}
        b = sockclnt_create.pack(args)
        self.write(b)
        msg = self.read_message()
        hdr, length = self.parent.header.unpack(msg, 0)
        if hdr.msgid != 16:
            # TODO: Add first numeric argument.
            raise VppTransportSocketIOError(1, 'Invalid reply message')

        r, length = sockclnt_create_reply.unpack(msg)
        self.socket_index = r.index
        for m in r.message_table:
            n = m.name
            self.message_table[n] = m.index

        self.start_reader_thread()

        return 0

    def disconnect(self):
        # TODO: Support repeated disconnect calls, recommend users to call
        # disconnect when they are not sure what the state is after failures.
        # TODO: Any volunteer for comprehensive docstrings?
        rv = 0
        try:
            # Might fail, if VPP closes socket before packet makes it out,
            # or if there was a failure during connect().
            rv = self.parent.api.sockclnt_delete(index=self.socket_index)
        except (IOError, vpp_papi.VPPApiError):
            pass
        self.connected = False
        self.stop_reading_thread()
        if self.socket is not None:
            self.socket.close()
        # Wipe message table, VPP can be restarted with different plugins.
        self.message_table = {}
        # Collect garbage.
        self.socket = None
        # Queues will be collected after connect replaces them.
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
        try:
            if self.remember_sent:
                self.last_sent = bytes(header) + bytes(buf)
            self.socket.sendall(header)
            self.socket.sendall(buf)
        except socket.error as err:
            raise VppTransportSocketIOError(1, 'Sendall error: {err!r}'.format(
                err=err))

    def _read_fixed(self, size):
        """Repeat receive until fixed size is read. Return empty on error."""
        buf = bytearray(size)
        view = memoryview(buf)
        left = size
        while 1:
            got = self.socket.recv_into(view, left)
            if got <= 0:
                # Read error.
                return ""
            if got >= left:
                # TODO: Raise if got > left?
                break
            left -= got
            view = view[got:]
        return buf

    def read_message(self):
        """Read single complete message, return it or empty on error.

        The message is returned as bytes, e.g. not deserialized yet.
        This is mainly called by the background reading thread.

        In high performance scenarios with reading thread stopped,
        users need to call this explicitly to avoid
        a deadlock (Unix Domain Socket buffers getting full).
        """
        hdr = self._read_fixed(16)
        if not hdr:
            return
        (_, hdrlen, _) = self.header.unpack(hdr)  # If at head of message

        # Read rest of message
        msg = self._read_fixed(hdrlen)
        if hdrlen == len(msg):
            return msg
        raise VppTransportSocketIOError(1, 'Unknown socket read error')

    def read(self, timeout=None):
        if not self.connected:
            raise VppTransportSocketIOError(1, 'Not connected')
        if timeout is None:
            timeout = self.read_timeout
        try:
            return self.q.get(True, timeout)
        except queue.Empty:
            return None
