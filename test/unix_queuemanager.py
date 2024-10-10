import socket
import pickle
import struct
import threading
import traceback
import queue
import select
import os
import tempfile
import uuid
import logging
import sys
import time

logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class UnixSocketQueue:
    def __init__(self):
        self.log = logging.getLogger('UnixSocketQueue')
        self.socket_dir = tempfile.mkdtemp(prefix='vpp_test_')
        self.socket_path = os.path.join(self.socket_dir, str(uuid.uuid4()))
        self.log.debug(f'Creating socket at {self.socket_path} %d' % os.getpid())
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.socket_path)
        self.sock.listen(5)
        self._stop = False
        self._accept_finished = False
        self._buffer = queue.Queue()
        self._thread = threading.Thread(target=self._accept_connections)
        self._thread.daemon = True
        self._thread.start()
        self.connections = []
        
    def _accept_connections(self):
        while not self._stop:
            try:
                readable, _, _ = select.select([self.sock], [], [], 0.1)
                if readable:
                    self.log.debug('Accepting new connection %d' %os.getpid())
                    client, _ = self.sock.accept()
                    self.connections.append(client)
                    self.log.debug('SLEEP for the new connection %d' % os.getpid())
                    time.sleep(1)
                    t = threading.Thread(target=self._handle_client, args=(client,))
                    t.daemon = True
                    t.start()
            except Exception as e:
                print(traceback.format_exc())
                self.log.exception('Error in accept loop')
                if not self._stop:
                    raise
        self._accept_finished = True

    def _handle_client(self, client):
        self.log.debug('Started handling client')
        size_struct = struct.Struct("!I")
        try:
            while not self._stop:
                size_data = client.recv(size_struct.size)
                if not size_data:
                    break
                size = size_struct.unpack(size_data)[0]
                self.log.debug(f'Receiving message of size {size}')
                
                data = b""
                while len(data) < size:
                    chunk = client.recv(min(size - len(data), 4096))
                    if not chunk:
                        return
                    data += chunk
                
                msg = pickle.loads(data)
                pid = os.getpid()
                self.log.debug(f'Received message: {msg} [ pid {pid} ]')
                self._buffer.put(msg)
                self.log.debug(f'Buffer: {self._buffer} {pid}')
        except Exception as e:
            print(traceback.format_exc())
            self.log.exception('Error handling client')
        finally:
            self.log.debug('Client handling finished')
            try:
                client.close()
            except Exception:
                pass
            if client in self.connections:
                self.connections.remove(client)

    def get(self, block=True, timeout=None):
        try:
            pid = os.getpid()
            self.log.debug(f'ABOUT TO GET MESSAGE {pid}')
            msg = self._buffer.get(block=block, timeout=timeout)
            self.log.debug(f'Getting message: {msg} {pid}')
            return msg
        except queue.Empty:
            return None

    def put(self, obj):
        pid = os.getpid()
        self.log.debug(f'local Putting message: {obj} [ pid {pid} ]')
        self._buffer.put(obj)
        return
    def send_to_remote(self, obj):
        data = pickle.dumps(obj)
        size = len(data)
        size_data = struct.pack("!I", size)
        
        for conn in list(self.connections):
            try:
                conn.sendall(size_data)
                conn.sendall(data)
                self.log.debug(f'Sent message to connection')
            except Exception as e:
                print(traceback.format_exc())
                self.log.exception('Error sending to connection')
                try:
                    conn.close()
                except Exception:
                    pass
                if conn in self.connections:
                    self.connections.remove(conn)

    def write(self, msg):
        pid = os.getpid()
        self.log.debug(f'Writing message: {msg} {pid}')
        self.put(msg)

    def flush(self):
        sys.__stdout__.flush()
        sys.__stderr__.flush()
        pass

    def fileno(self):
        return -1  # Return -1 to skip select() on this object

    def client_queue(self):
        return UnixSocketClient(self.socket_path)


    def close(self):
        self.log.debug('Closing queue')
        self._stop = True
        while not self._accept_finished:
            self.log.debug("Waiting for accept loop to stop...")
            time.sleep(0.1)

        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            os.unlink(self.socket_path)
            os.rmdir(self.socket_dir)
        except Exception:
            pass

class UnixSocketClient:
    def __init__(self, socket_path):
        self.log = logging.getLogger('UnixSocketClient')
        self.log.debug(f'Connecting to socket at {socket_path}')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(socket_path)
        self._buffer = queue.Queue()
        self._thread = threading.Thread(target=self._receive_data)
        self._thread.daemon = True
        self._stop = False
        self._thread.start()

    def _receive_data(self):
        pid = os.getpid()
        self.log.debug(f'Started receive thread in pid {pid}')
        size_struct = struct.Struct("!I")
        try:
            while not self._stop:
                size_data = self.sock.recv(size_struct.size)
                if not size_data:
                    break
                size = size_struct.unpack(size_data)[0]
                self.log.debug(f'Receiving message of size {size}')
                
                data = b""
                while len(data) < size:
                    chunk = self.sock.recv(min(size - len(data), 4096))
                    if not chunk:
                        return
                    data += chunk
                
                msg = pickle.loads(data)
                self.log.debug(f'Received message: {msg}')
                self._buffer.put(msg)
        except ConnectionResetError:        
            self.log.debug(f"CONNECTION RESET from control tower for pid {pid}")
            self._stop = true
            return
        except Exception as e:
            self.log.debug(traceback.format_exc())
            stack = traceback.extract_stack()
            self.log.debug(f"stack {stack}")
            self.log.exception(f'Error in receive thread pid {pid}')

    def get(self, block=True, timeout=None):
        try:
            pid = os.getpid()
            self.log.debug(f'XABOUT TO GET MESSAGE {pid} buffer: {self._buffer}')
            msg = self._buffer.get(block=block, timeout=timeout)
            self.log.debug(f'Getting message: {msg}')
            self.log.debug(f'XABOUT TO RETURN MESSAGE {pid}')
            return msg
        except queue.Empty:
            return None

    def put(self, obj):
        pid = os.getpid()
        self.log.debug(f'XPutting message: {obj} [ pid {pid} ]')
        data = pickle.dumps(obj)
        size = len(data)
        self.sock.sendall(struct.pack("!I", size))
        self.sock.sendall(data)

    def write(self, msg):
        if msg == "":
            self.log.debug(f'EMPTY MESSAGE, PID {pid}')
            return
        pid = os.getpid()
        self.log.debug(f'Writing message: {msg} {pid}')
        # print(msg, flush=True)  # Add direct print for debugging
        self.put(msg)

    def flush(self):
        pass

    def fileno(self):
        return -1  # Return -1 to skip select() on this object

    def close(self):
        self.log.debug('Closing client')
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass

class UnixSocketManager:
    def __init__(self):
        self.log = logging.getLogger('UnixSocketManager')
        self.queues = []

    def StreamQueue(self, ctx=None):
        self.log.debug('Creating new stream queue')
        queue = UnixSocketQueue()
        self.queues.append(queue)
        return queue
        return UnixSocketClient(queue.socket_path)
        # UnixSocketClient(queue.socket_path)

    def shutdown(self):
        self.log.debug('Shutting down manager')
        for queue in self.queues:
            queue.close()
