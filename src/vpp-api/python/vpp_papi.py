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
import sys, os, logging, collections, struct, json, threading, glob
import atexit, Queue

from cffi import FFI
ffi = FFI()
ffi.cdef("""
typedef void (*pneum_callback_t)(unsigned char * data, int len);
typedef void (*pneum_error_callback_t)(void *, unsigned char *, int);
int pneum_connect(char * name, char * chroot_prefix, pneum_callback_t cb,
    int rx_qlen);
int pneum_disconnect(void);
int pneum_read(char **data, int *l, unsigned short timeout);
int pneum_write(char *data, int len);
void pneum_free(void * msg);

int pneum_get_msg_index(unsigned char * name);
int pneum_msg_table_size(void);
int pneum_msg_table_max_index(void);

void pneum_rx_suspend (void);
void pneum_rx_resume (void);
void pneum_set_error_handler(pneum_error_callback_t);
 """)

# Barfs on failure, no need to check success.
vpp_api = ffi.dlopen('libpneum.so')

def vpp_atexit(self):
    """Clean up VPP connection on shutdown."""
    if self.connected:
        self.logger.debug('Cleaning up VPP on exit')
        self.disconnect()

vpp_object = None

@ffi.callback("void(unsigned char *, int)")
def pneum_callback_sync(data, len):
    vpp_object.msg_handler_sync(ffi.buffer(data, len))
@ffi.callback("void(unsigned char *, int)")
def pneum_callback_async(data, len):
    vpp_object.msg_handler_async(ffi.buffer(data, len))
@ffi.callback("void(void *, unsigned char *, int)")
def pneum_error_handler(arg, msg, msg_len):
    vpp_object.logger.warning("PNEUM: %s", ffi.string(msg, msg_len))

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
    def __init__(self, apifiles = None, testmode = False, async_thread = True,
                 logger = logging.getLogger('vpp_papi'), loglevel = 'debug'):
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
        self.buffersize = 10000
        self.connected = False
        self.header = struct.Struct('>HI')
        self.apifiles = []
        self.event_callback = None
        self.message_queue = Queue.Queue()
        self.read_timeout = 0
        self.vpp_api = vpp_api
        if async_thread:
            self.event_thread = threading.Thread(target=self.thread_msg_handler)
            self.event_thread.daemon = True
            self.event_thread.start()

        if not apifiles:
            # Pick up API definitions from default directory
            apifiles = glob.glob('/usr/share/vpp/api/*.api.json')

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
        vpp_api.pneum_set_error_handler(pneum_error_handler)

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

    def status(self):
        """Debug function: report current VPP API status to stdout."""
        print('Connected') if self.connected else print('Not Connected')
        print('Read API definitions from', ', '.join(self.apifiles))

    def __struct (self, t, n = None, e = -1, vl = None):
        """Create a packing structure for a message."""
        base_types = { 'u8' : 'B',
                       'u16' : 'H',
                       'u32' : 'I',
                       'i32' : 'i',
                       'u64' : 'Q',
                       'f64' : 'd',
                       }
        pack = None
        if t in base_types:
            pack = base_types[t]
            if not vl:
                if e > 0 and t == 'u8':
                    # Fixed byte array
                    return struct.Struct('>' + str(e) + 's')
                if e > 0:
                    # Fixed array of base type
                    return [e, struct.Struct('>' + base_types[t])]
                elif e == 0:
                    # Old style variable array
                    return [-1, struct.Struct('>' + base_types[t])]
            else:
                # Variable length array
                return [vl, struct.Struct('>s')] if t == 'u8' else \
                    [vl, struct.Struct('>' + base_types[t])]

            return struct.Struct('>' + base_types[t])

        if t in self.messages:
            ### Return a list in case of array ###
            if e > 0 and not vl:
                return [e, lambda self, encode, buf, offset, args: (
                    self.__struct_type(encode, self.messages[t], buf, offset,
                                       args))]
            if vl:
                return [vl, lambda self, encode, buf, offset, args: (
                    self.__struct_type(encode, self.messages[t], buf, offset,
                                       args))]
            elif e == 0:
                # Old style VLA
                raise NotImplementedError(1, 'No support for compound types ' + t)
            return lambda self, encode, buf, offset, args: (
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
                raise ValueError(1, 'Invalid field-name in message call ' + k)

        for k,v in msgdef['args'].iteritems():
            off += size
            if k in kwargs:
                if type(v) is list:
                    if callable(v[1]):
                        e = kwargs[v[0]] if v[0] in kwargs else v[0]
                        size = 0
                        for i in range(e):
                            size += v[1](self, True, buf, off + size,
                                         kwargs[k][i])
                    else:
                        if v[0] in kwargs:
                            l = kwargs[v[0]]
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
                        v.pack_into(buf, off, kwargs[k])
                        size = v.size
            else:
                size = v.size if not type(v) is list else 0

        return off + size - offset


    def __getitem__(self, name):
        if name in self.messages:
            return self.messages[name]
        return None

    def encode(self, msgdef, kwargs):
        # Make suitably large buffer
        buf = bytearray(self.buffersize)
        offset = 0
        size = self.__struct_type(True, msgdef, buf, offset, kwargs)
        return buf[:offset + size]

    def decode(self, msgdef, buf):
        return self.__struct_type(False, msgdef, buf, 0, None)[1]

    def __struct_type_decode(self, msgdef, buf, offset):
        res = []
        off = offset
        size = 0
        for k,v in msgdef['args'].iteritems():
            off += size
            if type(v) is list:
                lst = []
                if callable(v[1]): # compound type
                    size = 0
                    if v[0] in msgdef['args']: # vla
                        e = res[v[2]]
                    else: # fixed array
                        e = v[0]
                    res.append(lst)
                    for i in range(e):
                        (s,l) = v[1](self, False, buf, off + size, None)
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
                    (s,l) = v(self, False, buf, off, None)
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

    def add_message(self, name, msgdef, typeonly = False):
        if name in self.messages:
            raise ValueError('Duplicate message name: ' + name)

        args = collections.OrderedDict()
        argtypes = collections.OrderedDict()
        fields = []
        msg = {}
        for i, f in enumerate(msgdef):
            if type(f) is dict and 'crc' in f:
                msg['crc'] = f['crc']
                continue
            field_type = f[0]
            field_name = f[1]
            if len(f) == 3 and f[2] == 0 and i != len(msgdef) - 2:
                raise ValueError('Variable Length Array must be last: ' + name)
            args[field_name] = self.__struct(*f)
            argtypes[field_name] = field_type
            if len(f) == 4: # Find offset to # elements field
                args[field_name].append(args.keys().index(f[3]) - i)
            fields.append(field_name)
        msg['return_tuple'] = collections.namedtuple(name, fields,
                                                     rename = True)
        self.messages[name] = msg
        self.messages[name]['args'] = args
        self.messages[name]['argtypes'] = argtypes
        self.messages[name]['typeonly'] = typeonly
        return self.messages[name]

    def add_type(self, name, typedef):
        return self.add_message('vl_api_' + name + '_t', typedef, typeonly=True)

    def make_function(self, name, i, msgdef, multipart, async):
        if (async):
            f = lambda **kwargs: (self._call_vpp_async(i, msgdef, **kwargs))
        else:
            f = lambda **kwargs: (self._call_vpp(i, msgdef, multipart, **kwargs))
        args = self.messages[name]['args']
        argtypes = self.messages[name]['argtypes']
        f.__name__ = str(name)
        f.__doc__ = ", ".join(["%s %s" % (argtypes[k], k) for k in args.keys()])
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
        for name, msgdef in self.messages.iteritems():
            if self.messages[name]['typeonly']: continue
            crc = self.messages[name]['crc']
            n = name + '_' + crc[2:]
            i = vpp_api.pneum_get_msg_index(bytes(n))
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
                self.logger.debug('No such message type or failed CRC checksum: %s', n)

    def _write (self, buf):
        """Send a binary-packed message to VPP."""
        if not self.connected:
            raise IOError(1, 'Not connected')
        return vpp_api.pneum_write(str(buf), len(buf))

    def _read (self):
        if not self.connected:
            raise IOError(1, 'Not connected')
        mem = ffi.new("char **")
        size = ffi.new("int *")
        rv = vpp_api.pneum_read(mem, size, self.read_timeout)
        if rv:
            raise IOError(rv, 'pneum_read filed')
        msg = bytes(ffi.buffer(mem[0], size[0]))
        vpp_api.pneum_free(mem[0])
        return msg

    def connect_internal(self, name, msg_handler, chroot_prefix, rx_qlen, async):
	rv = vpp_api.pneum_connect(name, chroot_prefix, msg_handler, rx_qlen)
        if rv != 0:
            raise IOError(2, 'Connect failed')
        self.connected = True

        self.vpp_dictionary_maxid = vpp_api.pneum_msg_table_max_index()
        self._register_functions(async=async)

        # Initialise control ping
        crc = self.messages['control_ping']['crc']
        self.control_ping_index = \
                                  vpp_api.pneum_get_msg_index(
                                      bytes('control_ping' + '_' + crc[2:]))
        self.control_ping_msgdef = self.messages['control_ping']

    def connect(self, name, chroot_prefix = ffi.NULL,
                async = False, rx_qlen = 32):
        """Attach to VPP.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        async - if true, messages are sent without waiting for a reply
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """
        msg_handler = pneum_callback_sync if not async \
                      else pneum_callback_async
        return self.connect_internal(name, msg_handler, chroot_prefix, rx_qlen,
                                     async)

    def connect_sync (self, name, chroot_prefix = ffi.NULL, rx_qlen = 32):
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
        rv = vpp_api.pneum_disconnect()
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

        if not 'context' in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        vpp_api.pneum_rx_suspend()
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
                print('PNEUM ERROR: OH MY GOD')
                raise IOError(2, 'PNEUM read failed')

            r = self.decode_incoming_msg(msg)
            msgname = type(r).__name__
            if not context in r or r.context == 0 or context != r.context:
                self.message_queue.put_nowait(r)
                continue

            if not multipart:
                rl = r
                break
            if msgname == 'control_ping_reply':
                break

            rl.append(r)

        vpp_api.pneum_rx_resume()

        return rl

    def _call_vpp_async(self, i, msgdef, **kwargs):
        """Given a message, send the message and await a reply.

        msgdef - the message packing definition
        i - the message type index
        context - context number - chosen at random if not
        supplied.
        The remainder of the kwargs are the arguments to the API call.
        """
        if not 'context' in kwargs:
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
