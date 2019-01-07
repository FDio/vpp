#
# A transport class. With two implementations.
# One for socket and one for shared memory.
#

from cffi import FFI
import cffi

ffi = FFI()
ffi.cdef("""
typedef void (*vac_callback_t)(unsigned char * data, int len);
typedef void (*vac_error_callback_t)(void *, unsigned char *, int);
int vac_connect(char * name, char * chroot_prefix, vac_callback_t cb,
    int rx_qlen);
int vac_disconnect(void);
int vac_read(char **data, int *l, unsigned short timeout);
int vac_write(char *data, int len);
void vac_free(void * msg);

int vac_get_msg_index(unsigned char * name);
int vac_msg_table_size(void);
int vac_msg_table_max_index(void);

void vac_rx_suspend (void);
void vac_rx_resume (void);
void vac_set_error_handler(vac_error_callback_t);
 """)

vpp_object = None


@ffi.callback("void(unsigned char *, int)")
def vac_callback_sync(data, len):
    vpp_object.msg_handler_sync(ffi.buffer(data, len))


@ffi.callback("void(unsigned char *, int)")
def vac_callback_async(data, len):
    vpp_object.msg_handler_async(ffi.buffer(data, len))


@ffi.callback("void(void *, unsigned char *, int)")
def vac_error_handler(arg, msg, msg_len):
    vpp_object.logger.warning("VPP API client:: %s", ffi.string(msg, msg_len))


class VppTransportShmemIOError(IOError):
    pass


class VppTransport(object):
    VppTransportShmemIOError = VppTransportShmemIOError

    def __init__(self, parent, read_timeout, server_address, library_path):
        self.connected = False
        self.read_timeout = read_timeout
        self.parent = parent
        global vpp_object
        vpp_object = parent

        # Barfs on failure, no need to check success.
        self.vpp_api = ffi.dlopen(library_path)

        # Register error handler
        self.vpp_api.vac_set_error_handler(vac_error_handler)

        # Support legacy CFFI
        # from_buffer supported from 1.8.0
        (major, minor, patch) = [int(s) for s in
                                 cffi.__version__.split('.', 3)]
        if major >= 1 and minor >= 8:
            self.write = self._write_new_cffi
        else:
            self.write = self._write_legacy_cffi

    def connect(self, name, pfx, msg_handler, rx_qlen):
        self.connected = True
        if not pfx:
            pfx = ffi.NULL
        return self.vpp_api.vac_connect(name, pfx, msg_handler, rx_qlen)

    def disconnect(self):
        self.connected = False
        return self.vpp_api.vac_disconnect()

    def suspend(self):
        self.vpp_api.vac_rx_suspend()

    def resume(self):
        self.vpp_api.vac_rx_resume()

    def get_callback(self, do_async):
        return vac_callback_sync if not do_async else vac_callback_async

    def get_msg_index(self, name):
        return self.vpp_api.vac_get_msg_index(name)

    def msg_table_max_index(self):
        return self.vpp_api.vac_msg_table_max_index()

    def _write_new_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        return self.vpp_api.vac_write(ffi.from_buffer(buf), len(buf))

    def _write_legacy_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        return self.vpp_api.vac_write(bytes(buf), len(buf))

    def read(self):
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        mem = ffi.new("char **")
        size = ffi.new("int *")
        rv = self.vpp_api.vac_read(mem, size, self.read_timeout)
        if rv:
            raise VppTransportShmemIOError(rv, 'vac_read failed')
        msg = bytes(ffi.buffer(mem[0], size[0]))
        self.vpp_api.vac_free(mem[0])
        return msg
