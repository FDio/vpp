#!/usr/bin/env python
#
# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function
import sys
import os
import logging
import collections
import struct
import json
import threading
import fnmatch
import atexit
from cffi import FFI
import cffi

if sys.version[0] == '2':
    import Queue as queue
else:
    import queue as queue

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

# Barfs on failure, no need to check success.
vpp_api = ffi.dlopen('libvppapiclient.so')

def vpp_atexit(self):
    """Clean up VPP connection on shutdown."""
    if self.connected:
        self.logger.debug('Cleaning up VPP on exit')
        self.disconnect()

vpp_object = None


def vpp_iterator(d):
    if sys.version[0] == '2':
        return d.iteritems()
    else:
        return d.items()


@ffi.callback("void(unsigned char *, int)")
def vac_callback_sync(data, len):
    vpp_object.msg_handler_sync(ffi.buffer(data, len))


@ffi.callback("void(unsigned char *, int)")
def vac_callback_async(data, len):
    vpp_object.msg_handler_async(ffi.buffer(data, len))


@ffi.callback("void(void *, unsigned char *, int)")
def vac_error_handler(arg, msg, msg_len):
    vpp_object.logger.warning("VPP API client:: %s", ffi.string(msg, msg_len))


class Empty(object):
    pass


class FuncWrapper(object):
    def __init__(self, func):
        self._func = func
        self.__name__ = func.__name__

    def __call__(self, **kwargs):
        return self._func(**kwargs)


class VPP():
    """VPP interface.

    This class provides the APIs to VPP.  The APIs are loaded
    from provided .api.json files and makes functions accordingly.
    These functions are documented in the VPP .api files, as they
    are dynamically created.

    Additionally, VPP can send callback messages; this class
    provides a means to register a callback function to receive
    these messages in a background thread.
    """
    def __init__(self, apifiles=None, testmode=False, async_thread=True,
                 logger=logging.getLogger('vpp_papi'), loglevel='debug', read_timeout=0):
        """Create a VPP API object.

        apifiles is a list of files containing API
        descriptions that will be loaded - methods will be
        dynamically created reflecting these APIs.  If not
        provided this will load the API files from VPP's
        default install location.
        """
        global vpp_object
        vpp_object = self
        self.logger = logger
        logging.basicConfig(level=getattr(logging, loglevel.upper()))

        self.messages = {}
        self.id_names = []
        self.id_msgdef = []
        self.connected = False
        self.header = struct.Struct('>HI')
        self.apifiles = []
        self.event_callback = None
        self.message_queue = queue.Queue()
        self.read_timeout = read_timeout
        self.vpp_api = vpp_api
        if async_thread:
            self.event_thread = threading.Thread(
                target=self.thread_msg_handler)
            self.event_thread.daemon = True
            self.event_thread.start()

        if not apifiles:
            # Pick up API definitions from default directory
            try:
                apifiles = self.find_api_files()
            except RuntimeError:
                # In test mode we don't care that we can't find the API files
                if testmode:
                    apifiles = []
                else:
                    raise

        for file in apifiles:
            with open(file) as apidef_file:
                api = json.load(apidef_file)
                for t in api['types']:
                    self.add_type(t[0], t[1:])

                for m in api['messages']:
                    self.add_message(m[0], m[1:])
        self.apifiles = apifiles

        # Basic sanity check
        if len(self.messages) == 0 and not testmode:
            raise ValueError(1, 'Missing JSON message definitions')

        # Make sure we allow VPP to clean up the message rings.
        atexit.register(vpp_atexit, self)

        # Register error handler
        vpp_api.vac_set_error_handler(vac_error_handler)

        # Support legacy CFFI
        # from_buffer supported from 1.8.0
        (major, minor, patch) = [int(s) for s in cffi.__version__.split('.', 3)]
        if major >= 1 and minor >= 8:
            self._write = self._write_new_cffi
        else:
            self._write = self._write_legacy_cffi

    class ContextId(object):
        """Thread-safe provider of unique context IDs."""
        def __init__(self):
            self.context = 0
            self.lock = threading.Lock()

        def __call__(self):
            """Get a new unique (or, at least, not recently used) context."""
            with self.lock:
                self.context += 1
                return self.context
    get_context = ContextId()

    @classmethod
    def find_api_dir(cls):
        """Attempt to find the best directory in which API definition
        files may reside. If the value VPP_API_DIR exists in the environment
        then it is first on the search list. If we're inside a recognized
        location in a VPP source tree (src/scripts and src/vpp-api/python)
        then entries from there to the likely locations in build-root are
        added. Finally the location used by system packages is added.

        :returns: A single directory name, or None if no such directory
            could be found.
        """
        dirs = []

        if 'VPP_API_DIR' in os.environ:
            dirs.append(os.environ['VPP_API_DIR'])

        # perhaps we're in the 'src/scripts' or 'src/vpp-api/python' dir;
        # in which case, plot a course to likely places in the src tree
        import __main__ as main
        if hasattr(main, '__file__'):
            # get the path of the calling script
            localdir = os.path.dirname(os.path.realpath(main.__file__))
        else:
            # use cwd if there is no calling script
            localdir = os.cwd()
        localdir_s = localdir.split(os.path.sep)

        def dmatch(dir):
            """Match dir against right-hand components of the script dir"""
            d = dir.split('/')  # param 'dir' assumes a / separator
            l = len(d)
            return len(localdir_s) > l and localdir_s[-l:] == d

        def sdir(srcdir, variant):
            """Build a path from srcdir to the staged API files of
            'variant'  (typically '' or '_debug')"""
            # Since 'core' and 'plugin' files are staged
            # in separate directories, we target the parent dir.
            return os.path.sep.join((
                srcdir,
                'build-root',
                'install-vpp%s-native' % variant,
                'vpp',
                'share',
                'vpp',
                'api',
            ))

        srcdir = None
        if dmatch('src/scripts'):
            srcdir = os.path.sep.join(localdir_s[:-2])
        elif dmatch('src/vpp-api/python'):
            srcdir = os.path.sep.join(localdir_s[:-3])
        elif dmatch('test'):
            # we're apparently running tests
            srcdir = os.path.sep.join(localdir_s[:-1])

        if srcdir:
            # we're in the source tree, try both the debug and release
            # variants.
            x = 'vpp/share/vpp/api'
            dirs.append(sdir(srcdir, '_debug'))
            dirs.append(sdir(srcdir, ''))

        # Test for staged copies of the scripts
        # For these, since we explicitly know if we're running a debug versus
        # release variant, target only the relevant directory
        if dmatch('build-root/install-vpp_debug-native/vpp/bin'):
            srcdir = os.path.sep.join(localdir_s[:-4])
            dirs.append(sdir(srcdir, '_debug'))
        if dmatch('build-root/install-vpp-native/vpp/bin'):
            srcdir = os.path.sep.join(localdir_s[:-4])
            dirs.append(sdir(srcdir, ''))

        # finally, try the location system packages typically install into
        dirs.append(os.path.sep.join(('', 'usr', 'share', 'vpp', 'api')))

        # check the directories for existance; first one wins
        for dir in dirs:
            if os.path.isdir(dir):
                return dir

        return None

    @classmethod
    def find_api_files(cls, api_dir=None, patterns='*'):
        """Find API definition files from the given directory tree with the
        given pattern. If no directory is given then find_api_dir() is used
        to locate one. If no pattern is given then all definition files found
        in the directory tree are used.

        :param api_dir: A directory tree in which to locate API definition
            files; subdirectories are descended into.
            If this is None then find_api_dir() is called to discover it.
        :param patterns: A list of patterns to use in each visited directory
            when looking for files.
            This can be a list/tuple object or a comma-separated string of
            patterns. Each value in the list will have leading/trialing
            whitespace stripped.
            The pattern specifies the first part of the filename, '.api.json'
            is appended.
            The results are de-duplicated, thus overlapping patterns are fine.
            If this is None it defaults to '*' meaning "all API files".
        :returns: A list of file paths for the API files found.
        """
        if api_dir is None:
            api_dir = cls.find_api_dir()
            if api_dir is None:
                raise RuntimeError("api_dir cannot be located")

        if isinstance(patterns, list) or isinstance(patterns, tuple):
            patterns = [p.strip() + '.api.json' for p in patterns]
        else:
            patterns = [p.strip() + '.api.json' for p in patterns.split(",")]

        api_files = []
        for root, dirnames, files in os.walk(api_dir):
            # iterate all given patterns and de-dup the result
            files = set(sum([fnmatch.filter(files, p) for p in patterns], []))
            for filename in files:
                api_files.append(os.path.join(root, filename))

        return api_files

    def status(self):
        """Debug function: report current VPP API status to stdout."""
        print('Connected') if self.connected else print('Not Connected')
        print('Read API definitions from', ', '.join(self.apifiles))

    def __struct(self, t, n=None, e=-1, vl=None):
        """Create a packing structure for a message."""
        base_types = {'u8': 'B',
                      'u16': 'H',
                      'u32': 'I',
                      'i32': 'i',
                      'u64': 'Q',
                      'f64': 'd', }
        pack = None
        if t in base_types:
            pack = base_types[t]
            if not vl:
                if e > 0 and t == 'u8':
                    # Fixed byte array
                    s = struct.Struct('>' + str(e) + 's')
                    return s.size, s
                if e > 0:
                    # Fixed array of base type
                    s = struct.Struct('>' + base_types[t])
                    return s.size, [e, s]
                elif e == 0:
                    # Old style variable array
                    s = struct.Struct('>' + base_types[t])
                    return s.size, [-1, s]
            else:
                # Variable length array
                if t == 'u8':
                    s = struct.Struct('>s')
                    return s.size, [vl, s]
                else:
                    s = struct.Struct('>' + base_types[t])
                return s.size, [vl, s]

            s = struct.Struct('>' + base_types[t])
            return s.size, s

        if t in self.messages:
            size = self.messages[t]['sizes'][0]

            # Return a list in case of array
            if e > 0 and not vl:
                return size, [e, lambda self, encode, buf, offset, args: (
                    self.__struct_type(encode, self.messages[t], buf, offset,
                                       args))]
            if vl:
                return size, [vl, lambda self, encode, buf, offset, args: (
                    self.__struct_type(encode, self.messages[t], buf, offset,
                                       args))]
            elif e == 0:
                # Old style VLA
                raise NotImplementedError(1,
                                          'No support for compound types ' + t)
            return size, lambda self, encode, buf, offset, args: (
                self.__struct_type(encode, self.messages[t], buf, offset, args)
            )

        raise ValueError(1, 'Invalid message type: ' + t)

    def __struct_type(self, encode, msgdef, buf, offset, kwargs):
        """Get a message packer or unpacker."""
        if encode:
            return self.__struct_type_encode(msgdef, buf, offset, kwargs)
        else:
            return self.__struct_type_decode(msgdef, buf, offset)

    def __struct_type_encode(self, msgdef, buf, offset, kwargs):
        off = offset
        size = 0

        for k in kwargs:
            if k not in msgdef['args']:
                raise ValueError(1,'Non existing argument [' + k + ']' + \
                                 ' used in call to: ' + \
                                 self.id_names[kwargs['_vl_msg_id']] + '()' )

        for k, v in vpp_iterator(msgdef['args']):
            off += size
            if k in kwargs:
                if type(v) is list:
                    if callable(v[1]):
                        e = kwargs[v[0]] if v[0] in kwargs else v[0]
                        if e != len(kwargs[k]):
                            raise (ValueError(1, 'Input list length mismatch: %s (%s != %s)' %  (k, e, len(kwargs[k]))))
                        size = 0
                        for i in range(e):
                            size += v[1](self, True, buf, off + size,
                                         kwargs[k][i])
                    else:
                        if v[0] in kwargs:
                            l = kwargs[v[0]]
                            if l != len(kwargs[k]):
                                raise ValueError(1, 'Input list length mismatch: %s (%s != %s)' % (k, l, len(kwargs[k])))
                        else:
                            l = len(kwargs[k])
                        if v[1].size == 1:
                            buf[off:off + l] = bytearray(kwargs[k])
                            size = l
                        else:
                            size = 0
                            for i in kwargs[k]:
                                v[1].pack_into(buf, off + size, i)
                                size += v[1].size
                else:
                    if callable(v):
                        size = v(self, True, buf, off, kwargs[k])
                    else:
                        if type(kwargs[k]) is str and v.size < len(kwargs[k]):
                            raise ValueError(1, 'Input list length mismatch: %s (%s < %s)' % (k, v.size, len(kwargs[k])))
                        v.pack_into(buf, off, kwargs[k])
                        size = v.size
            else:
                size = v.size if not type(v) is list else 0

        return off + size - offset

    def __getitem__(self, name):
        if name in self.messages:
            return self.messages[name]
        return None

    def get_size(self, sizes, kwargs):
        total_size = sizes[0]
        for e in sizes[1]:
            if e in kwargs and type(kwargs[e]) is list:
                total_size += len(kwargs[e]) * sizes[1][e]
        return total_size

    def encode(self, msgdef, kwargs):
        # Make suitably large buffer
        size = self.get_size(msgdef['sizes'], kwargs)
        buf = bytearray(size)
        offset = 0
        size = self.__struct_type(True, msgdef, buf, offset, kwargs)
        return buf[:offset + size]

    def decode(self, msgdef, buf):
        return self.__struct_type(False, msgdef, buf, 0, None)[1]

    def __struct_type_decode(self, msgdef, buf, offset):
        res = []
        off = offset
        size = 0
        for k, v in vpp_iterator(msgdef['args']):
            off += size
            if type(v) is list:
                lst = []
                if callable(v[1]):  # compound type
                    size = 0
                    if v[0] in msgdef['args']:  # vla
                        e = res[v[2]]
                    else:  # fixed array
                        e = v[0]
                    res.append(lst)
                    for i in range(e):
                        (s, l) = v[1](self, False, buf, off + size, None)
                        lst.append(l)
                        size += s
                    continue
                if v[1].size == 1:
                    if type(v[0]) is int:
                        size = len(buf) - off
                    else:
                        size = res[v[2]]
                    res.append(buf[off:off + size])
                else:
                    e = v[0] if type(v[0]) is int else res[v[2]]
                    if e == -1:
                        e = (len(buf) - off) / v[1].size
                    lst = []
                    res.append(lst)
                    size = 0
                    for i in range(e):
                        lst.append(v[1].unpack_from(buf, off + size)[0])
                        size += v[1].size
            else:
                if callable(v):
                    size = 0
                    (s, l) = v(self, False, buf, off, None)
                    res.append(l)
                    size += s
                else:
                    res.append(v.unpack_from(buf, off)[0])
                    size = v.size

        return off + size - offset, msgdef['return_tuple']._make(res)

    def ret_tup(self, name):
        if name in self.messages and 'return_tuple' in self.messages[name]:
            return self.messages[name]['return_tuple']
        return None

    def add_message(self, name, msgdef, typeonly=False):
        if name in self.messages:
            raise ValueError('Duplicate message name: ' + name)

        args = collections.OrderedDict()
        argtypes = collections.OrderedDict()
        fields = []
        msg = {}
        total_size = 0
        sizes = {}
        for i, f in enumerate(msgdef):
            if type(f) is dict and 'crc' in f:
                msg['crc'] = f['crc']
                continue
            field_type = f[0]
            field_name = f[1]
            if len(f) == 3 and f[2] == 0 and i != len(msgdef) - 2:
                raise ValueError('Variable Length Array must be last: ' + name)
            size, s = self.__struct(*f)
            args[field_name] = s
            if type(s) == list and type(s[0]) == int and type(s[1]) == struct.Struct:
                if s[0] < 0:
                    sizes[field_name] = size
                else:
                    sizes[field_name] = size
                    total_size += s[0] * size
            else:
                sizes[field_name] = size
                total_size += size

            argtypes[field_name] = field_type
            if len(f) == 4:  # Find offset to # elements field
                idx = list(args.keys()).index(f[3]) - i
                args[field_name].append(idx)
            fields.append(field_name)
        msg['return_tuple'] = collections.namedtuple(name, fields,
                                                     rename=True)
        self.messages[name] = msg
        self.messages[name]['args'] = args
        self.messages[name]['argtypes'] = argtypes
        self.messages[name]['typeonly'] = typeonly
        self.messages[name]['sizes'] = [total_size, sizes]
        return self.messages[name]

    def add_type(self, name, typedef):
        return self.add_message('vl_api_' + name + '_t', typedef,
                                typeonly=True)

    def make_function(self, name, i, msgdef, multipart, async):
        if (async):
            f = lambda **kwargs: (self._call_vpp_async(i, msgdef, **kwargs))
        else:
            f = lambda **kwargs: (self._call_vpp(i, msgdef, multipart,
                                                 **kwargs))
        args = self.messages[name]['args']
        argtypes = self.messages[name]['argtypes']
        f.__name__ = str(name)
        f.__doc__ = ", ".join(["%s %s" %
                               (argtypes[k], k) for k in args.keys()])
        return f

    @property
    def api(self):
        if not hasattr(self, "_api"):
            raise Exception("Not connected, api definitions not available")
        return self._api

    def _register_functions(self, async=False):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        self._api = Empty()
        for name, msgdef in vpp_iterator(self.messages):
            if self.messages[name]['typeonly']:
                continue
            crc = self.messages[name]['crc']
            n = name + '_' + crc[2:]
            i = vpp_api.vac_get_msg_index(n.encode())
            if i > 0:
                self.id_msgdef[i] = msgdef
                self.id_names[i] = name
                multipart = True if name.find('_dump') > 0 else False
                f = self.make_function(name, i, msgdef, multipart, async)
                setattr(self._api, name, FuncWrapper(f))

                # old API stuff starts here - will be removed in 17.07
                if hasattr(self, name):
                    raise NameError(
                        3, "Conflicting name in JSON definition: `%s'" % name)
                setattr(self, name, f)
                # old API stuff ends here
            else:
                self.logger.debug(
                    'No such message type or failed CRC checksum: %s', n)

    def _write_new_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise IOError(1, 'Not connected')
        return vpp_api.vac_write(ffi.from_buffer(buf), len(buf))

    def _write_legacy_cffi(self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise IOError(1, 'Not connected')
        return vpp_api.vac_write(str(buf), len(buf))

    def _read(self):
        if not self.connected:
            raise IOError(1, 'Not connected')
        mem = ffi.new("char **")
        size = ffi.new("int *")
        rv = vpp_api.vac_read(mem, size, self.read_timeout)
        if rv:
            raise IOError(rv, 'vac_read failed')
        msg = bytes(ffi.buffer(mem[0], size[0]))
        vpp_api.vac_free(mem[0])
        return msg

    def connect_internal(self, name, msg_handler, chroot_prefix, rx_qlen,
                         async):
        pfx = chroot_prefix.encode() if chroot_prefix else ffi.NULL
        rv = vpp_api.vac_connect(name.encode(), pfx, msg_handler, rx_qlen)
        if rv != 0:
            raise IOError(2, 'Connect failed')
        self.connected = True

        self.vpp_dictionary_maxid = vpp_api.vac_msg_table_max_index()
        self._register_functions(async=async)

        # Initialise control ping
        crc = self.messages['control_ping']['crc']
        self.control_ping_index = vpp_api.vac_get_msg_index(
            ('control_ping' + '_' + crc[2:]).encode())
        self.control_ping_msgdef = self.messages['control_ping']
        return rv

    def connect(self, name, chroot_prefix=None, async=False, rx_qlen=32):
        """Attach to VPP.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        async - if true, messages are sent without waiting for a reply
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """
        msg_handler = vac_callback_sync if not async else vac_callback_async
        return self.connect_internal(name, msg_handler, chroot_prefix, rx_qlen,
                                     async)

    def connect_sync(self, name, chroot_prefix=None, rx_qlen=32):
        """Attach to VPP in synchronous mode. Application must poll for events.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """

        return self.connect_internal(name, ffi.NULL, chroot_prefix, rx_qlen,
                                     async=False)

    def disconnect(self):
        """Detach from VPP."""
        rv = vpp_api.vac_disconnect()
        self.connected = False
        return rv

    def msg_handler_sync(self, msg):
        """Process an incoming message from VPP in sync mode.

        The message may be a reply or it may be an async notification.
        """
        r = self.decode_incoming_msg(msg)
        if r is None:
            return

        # If we have a context, then use the context to find any
        # request waiting for a reply
        context = 0
        if hasattr(r, 'context') and r.context > 0:
            context = r.context

        msgname = type(r).__name__

        if context == 0:
            # No context -> async notification that we feed to the callback
            self.message_queue.put_nowait(r)
        else:
            raise IOError(2, 'RPC reply message received in event handler')

    def decode_incoming_msg(self, msg):
        if not msg:
            self.logger.warning('vpp_api.read failed')
            return

        i, ci = self.header.unpack_from(msg, 0)
        if self.id_names[i] == 'rx_thread_exit':
            return

        #
        # Decode message and returns a tuple.
        #
        msgdef = self.id_msgdef[i]
        if not msgdef:
            raise IOError(2, 'Reply message undefined')

        r = self.decode(msgdef, msg)

        return r

    def msg_handler_async(self, msg):
        """Process a message from VPP in async mode.

        In async mode, all messages are returned to the callback.
        """
        r = self.decode_incoming_msg(msg)
        if r is None:
            return

        msgname = type(r).__name__

        if self.event_callback:
            self.event_callback(msgname, r)

    def _control_ping(self, context):
        """Send a ping command."""
        self._call_vpp_async(self.control_ping_index,
                             self.control_ping_msgdef,
                             context=context)

    def _call_vpp(self, i, msgdef, multipart, **kwargs):
        """Given a message, send the message and await a reply.

        msgdef - the message packing definition
        i - the message type index
        multipart - True if the message returns multiple
        messages in return.
        context - context number - chosen at random if not
        supplied.
        The remainder of the kwargs are the arguments to the API call.

        The return value is the message or message array containing
        the response.  It will raise an IOError exception if there was
        no response within the timeout window.
        """

        if 'context' not in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        vpp_api.vac_rx_suspend()
        self._write(b)

        if multipart:
            # Send a ping after the request - we use its response
            # to detect that we have seen all results.
            self._control_ping(context)

        # Block until we get a reply.
        rl = []
        while (True):
            msg = self._read()
            if not msg:
                raise IOError(2, 'VPP API client: read failed')

            r = self.decode_incoming_msg(msg)
            msgname = type(r).__name__
            if context not in r or r.context == 0 or context != r.context:
                self.message_queue.put_nowait(r)
                continue

            if not multipart:
                rl = r
                break
            if msgname == 'control_ping_reply':
                break

            rl.append(r)

        vpp_api.vac_rx_resume()

        return rl

    def _call_vpp_async(self, i, msgdef, **kwargs):
        """Given a message, send the message and await a reply.

        msgdef - the message packing definition
        i - the message type index
        context - context number - chosen at random if not
        supplied.
        The remainder of the kwargs are the arguments to the API call.
        """
        if 'context' not in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        self._write(b)

    def register_event_callback(self, callback):
        """Register a callback for async messages.

        This will be called for async notifications in sync mode,
        and all messages in async mode.  In sync mode, replies to
        requests will not come here.

        callback is a fn(msg_type_name, msg_type) that will be
        called when a message comes in.  While this function is
        executing, note that (a) you are in a background thread and
        may wish to use threading.Lock to protect your datastructures,
        and (b) message processing from VPP will stop (so if you take
        a long while about it you may provoke reply timeouts or cause
        VPP to fill the RX buffer).  Passing None will disable the
        callback.
        """
        self.event_callback = callback

    def thread_msg_handler(self):
        """Python thread calling the user registerd message handler.

        This is to emulate the old style event callback scheme. Modern
        clients should provide their own thread to poll the event
        queue.
        """
        while True:
            r = self.message_queue.get()
            msgname = type(r).__name__
            if self.event_callback:
                self.event_callback(msgname, r)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
