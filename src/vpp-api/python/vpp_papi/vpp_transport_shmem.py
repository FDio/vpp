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
void vac_mem_init (size_t size);
""")

vpp_object = None

# allow file to be imported so it can be mocked in tests.
# If the shared library fails, VppTransport cannot be initialized.
try:
    vpp_api = ffi.dlopen('libvppapiclient.so')
except OSError:
    vpp_api = None


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
    """ exception communicating with vpp over shared memory """

    def __init__(self, rv, descr):
        self.rv = rv
        self.desc = descr

        super(VppTransportShmemIOError, self).__init__(rv, descr)


class VppTransport(object):
    VppTransportShmemIOError = VppTransportShmemIOError

    def __init__(self, parent, read_timeout, server_address):
        self.connected = False
        self.read_timeout = read_timeout
        self.parent = parent
        global vpp_object
        vpp_object = parent

        vpp_api.vac_mem_init(0)

        # Register error handler
        vpp_api.vac_set_error_handler(vac_error_handler)

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
        return vpp_api.vac_connect(name.encode('ascii'), pfx, msg_handler, rx_qlen)

    def disconnect(self):
        self.connected = False
        return vpp_api.vac_disconnect()

    def suspend(self):
        vpp_api.vac_rx_suspend()

    def resume(self):
        vpp_api.vac_rx_resume()

    def get_callback(self, do_async):
        return vac_callback_sync if not do_async else vac_callback_async

    def get_msg_index(self, name):
        return vpp_api.vac_get_msg_index(name.encode('ascii'))

    def msg_table_max_index(self):
        return vpp_api.vac_msg_table_max_index()

    def _write_new_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        return vpp_api.vac_write(ffi.from_buffer(buf), len(buf))

    def _write_legacy_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        return vpp_api.vac_write(bytes(buf), len(buf))

    def read(self, timeout=None):
        if not self.connected:
            raise VppTransportShmemIOError(1, 'Not connected')
        if timeout is None:
            timeout = self.read_timeout
        mem = ffi.new("char **")
        size = ffi.new("int *")
        rv = vpp_api.vac_read(mem, size, timeout)
        if rv:
            strerror = 'vac_read failed.  It is likely that VPP died.'
            raise VppTransportShmemIOError(rv, strerror)
        msg = bytes(ffi.buffer(mem[0], size[0]))
        vpp_api.vac_free(mem[0])
        return msg
