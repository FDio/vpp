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

from cffi import FFI
ffi = FFI()
ffi.cdef("""
typedef void (*pneum_callback_t)(unsigned char * data, int len);
int pneum_connect(char * name, char * chroot_prefix, pneum_callback_t cb,
int rx_len);
int pneum_disconnect(void);
int pneum_read(char **data, int *l, unsigned int timeout);
int pneum_write(char *data, int len);
int pneum_msg_table_max_index(void);
int pneum_get_msg_index (unsigned char * name);
void pneum_free (void * msg);
int pneum_lock_queue (void);
int pneum_unlock_queue (void);

 """)

pneum = ffi.dlopen('libpneum.so')

import sys, os, logging, collections, struct, json, threading, glob
import ctypes, Queue
logging.basicConfig(level=logging.DEBUG)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

vpp_object = None

@ffi.callback("void(unsigned char *, int)")
def pneum_callback(data, len):
    vpp_object.msg_handler(ffi.buffer(data, len))

class VPP():
    def __init__(self, apifiles = None, testmode = False):
        self.messages = {}
        self.id_names = []
        self.id_msgdef = []
        self.buffersize = 10000
        self.connected = False
        self.header = struct.Struct('>HI')
        self.timeout = 5
        self.apifile = []
        self.message_queue = Queue.Queue()

        if not apifiles:
            # Pick up API definitions from default directory
            apifiles = glob.glob('/usr/share/vpp/api/*.api.json')

        for file in apifiles:
            self.apifile.append(file)
            with open(file) as apidef_file:
                api = json.load(apidef_file)
                for t in api['types']:
                    self.add_type(t[0], t[1:])

                for m in api['messages']:
                    self.add_message(m[0], m[1:])

        # Basic sanity check
        if len(self.messages) == 0 and not testmode:
            raise ValueError(1, 'Missing JSON message definitions')


    class ContextId(object):
        def __init__(self):
            self.context = 0
        def __call__(self):
            self.context += 1
            return self.context
    get_context = ContextId()

    def status(self):
        print('Connected') if self.connected else print('Not Connected')
        print('Read API definitions from', self.apifile)

    def __struct (self, t, n = None, e = -1, vl = None):
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
        if not async:
            f = lambda **kwargs: (self._call_vpp(i, name, msgdef, multipart,
                                                 **kwargs))
        else:
            f = lambda **kwargs: (self._call_vpp_async(i, name, msgdef,
                                                       multipart,
                                                       **kwargs))

        args = self.messages[name]['args']
        argtypes = self.messages[name]['argtypes']
        f.__name__ = str(name)
        f.__doc__ = ", ".join(["%s %s" % (argtypes[k], k) for k in args.keys()])
        return f

    def _register_functions(self, async):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        for name, msgdef in self.messages.iteritems():
            if self.messages[name]['typeonly']: continue
            crc = self.messages[name]['crc']
            n = name + '_' + crc[2:]
            i = pneum.pneum_get_msg_index(bytes(n))
            if i > 0:
                self.id_msgdef[i] = msgdef
                self.id_names[i] = name
                multipart = True if name.find('_dump') > 0 else False
                setattr(self, name,
                        self.make_function(name, i, msgdef, multipart, async))
            else:
                eprint('No such message type or failed CRC checksum ' + n)

    def _write (self, buf):
        if not self.connected:
            raise IOError(1, 'Not connected')
        return pneum.pneum_write(str(buf), len(buf))

    def _read (self):
        if not self.connected:
            raise IOError(1, 'Not connected')

        mem = ffi.new("char **")
        size = ffi.new("int *")
        rv = pneum.pneum_read(mem, size, 0)
        if rv:
            raise IOError(rv, 'pneum read failed')
        # Copy the message into bytestring
        msg = bytes(ffi.buffer(mem[0], size[0]))
        pneum.pneum_free(mem[0])
        return msg

    def connect(self, name, chroot_prefix = ffi.NULL, async = False,
                rx_qlen = 32):
        global vpp_object
        vpp_object = self

        rv = pneum.pneum_connect(name, chroot_prefix, pneum_callback, rx_qlen)

        if rv != 0:
            raise IOError(2, 'Connect failed')
        self.connected = True

        self.vpp_dictionary_maxid = pneum.pneum_msg_table_max_index()
        self._register_functions(async)

        # Initialise control ping
        crc = self.messages['control_ping']['crc']
        self.control_ping_index = pneum.pneum_get_msg_index( \
            bytes('control_ping' + '_' + crc[2:]))
        self.control_ping_msgdef = self.messages['control_ping']

    def disconnect(self):
        rv = pneum.pneum_disconnect()
        return rv

    def msg_handler(self, msg):
        if not msg:
            eprint('pneum.read failed')
            return

        i, ci = self.header.unpack_from(msg, 0)
        if self.id_names[i] == 'rx_thread_exit':
            return;

        #
        # Decode message and returns a tuple.
        #
        msgdef = self.id_msgdef[i]
        if not msgdef:
            raise IOError(2, 'Reply message undefined')

        r = self.decode(msgdef, msg)
        self.message_queue.put_nowait(r)

    def _control_ping(self, context):
        self._write(self.encode(self.control_ping_msgdef,
                        { '_vl_msg_id' : self.control_ping_index,
                          'context' : context}))

    def _call_vpp(self, i, name, msgdef, multipart, **kwargs):
        if not 'context' in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        ## LOGGINGprint('Calling name', name, context)

        pneum.pneum_lock_queue()

        rv = self._write(self.encode(msgdef, kwargs))

        if multipart:
            self._control_ping(context)
        rl = []


        while (True):
            msg = self._read()
            if not msg:
                raise IOError(2, 'PNEUM read failed')

            i, ci = self.header.unpack_from(msg, 0)
            msgdef = self.id_msgdef[i]
            if not msgdef:
                raise IOError(2, 'Reply message undefined')

            r = self.decode(msgdef, msg)

            msgname = type(r).__name__
            if not context in r or r.context == 0 or context != r.context:
                self.message_queue.put_nowait(r)
                continue

            # LOGGINGprint('Received', msgname)
            if not multipart:
                rl = r
                break
            if msgname == 'control_ping_reply':
                break

            rl.append(r)
            ###TODO HOW TO DEAL WITH EXCEPTIONS and unlocking the queue
        pneum.pneum_unlock_queue()
        return rl

    def _call_vpp_async(self, i, msgdef, multipart, **kwargs):
        if not 'context' in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        self._write(b)

