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
logging.basicConfig(level=logging.DEBUG)
import vpp_api

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class VPP():
    def __init__(self, apifiles = None, testmode = False):
        self.messages = {}
        self.id_names = []
        self.id_msgdef = []
        self.buffersize = 10000
        self.connected = False
        self.header = struct.Struct('>HI')
        self.results = {}
        self.timeout = 5
        self.apifile = []

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

    def add_message(self, name, msgdef):
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
        return self.messages[name]

    def add_type(self, name, typedef):
        return self.add_message('vl_api_' + name + '_t', typedef)

    def make_function(self, name, i, msgdef, multipart, async):
        if (async):
            f = lambda **kwargs: (self._call_vpp_async(i, msgdef, multipart, **kwargs))
        else:
            f = lambda **kwargs: (self._call_vpp(i, msgdef, multipart, **kwargs))
        args = self.messages[name]['args']
        argtypes = self.messages[name]['argtypes']
        f.__name__ = str(name)
        f.__doc__ = ", ".join(["%s %s" % (argtypes[k], k) for k in args.keys()])
        return f

    def _register_functions(self, async=False):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        for name, msgdef in self.messages.iteritems():
            if name in self.vpp_dictionary:
                if self.messages[name]['crc'] != self.vpp_dictionary[name]['crc']:
                    raise ValueError(3, 'Failed CRC checksum ' + name +
                                     ' ' + self.messages[name]['crc'] +
                                     ' ' + self.vpp_dictionary[name]['crc'])
                i = self.vpp_dictionary[name]['id']
                self.id_msgdef[i] = msgdef
                self.id_names[i] = name
                multipart = True if name.find('_dump') > 0 else False
                setattr(self, name, self.make_function(name, i, msgdef, multipart, async))

    def _write (self, buf):
        if not self.connected:
            raise IOError(1, 'Not connected')
        return vpp_api.write(str(buf))

    def _load_dictionary(self):
        self.vpp_dictionary = {}
        self.vpp_dictionary_maxid = 0
        d = vpp_api.msg_table()

        if not d:
            raise IOError(3, 'Cannot get VPP API dictionary')
        for i,n in d:
            name, crc =  n.rsplit('_', 1)
            crc = '0x' + crc
            self.vpp_dictionary[name] = { 'id' : i, 'crc' : crc }
            self.vpp_dictionary_maxid = max(self.vpp_dictionary_maxid, i)

    def connect(self, name, chroot_prefix = None, async = False):
        msg_handler = self.msg_handler if not async else self.msg_handler_async
        if not chroot_prefix:
            rv = vpp_api.connect(name, msg_handler)
        else:
            rv = vpp_api.connect(name, msg_handler, chroot_prefix)

        if rv != 0:
            raise IOError(2, 'Connect failed')
        self.connected = True

        self._load_dictionary()
        self._register_functions(async=async)

        # Initialise control ping
        self.control_ping_index = self.vpp_dictionary['control_ping']['id']
        self.control_ping_msgdef = self.messages['control_ping']

    def disconnect(self):
        rv = vpp_api.disconnect()
        return rv

    def results_wait(self, context):
        return (self.results[context]['e'].wait(self.timeout))

    def results_prepare(self, context):
        self.results[context] = {}
        self.results[context]['e'] = threading.Event()
        self.results[context]['e'].clear()
        self.results[context]['r'] = []

    def results_clean(self, context):
        del self.results[context]

    def msg_handler(self, msg):
        if not msg:
            eprint('vpp_api.read failed')
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
        if 'context' in r._asdict():
            if r.context > 0:
                context = r.context

        msgname = type(r).__name__

        #
        # XXX: Call provided callback for event
        # Are we guaranteed to not get an event during processing of other messages?
        # How to differentiate what's a callback message and what not? Context = 0?
        #
        #if not is_waiting_for_reply():
        if r.context == 0 and self.event_callback:
            self.event_callback(msgname, r)
            return

        #
        # Collect results until control ping
        #
        if msgname == 'control_ping_reply':
            self.results[context]['e'].set()
            return

        if not context in self.results:
            eprint('Not expecting results for this context', context, r)
            return

        if 'm' in self.results[context]:
            self.results[context]['r'].append(r)
            return

        self.results[context]['r'] = r
        self.results[context]['e'].set()

    def msg_handler_async(self, msg):
        if not msg:
            eprint('vpp_api.read failed')
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
        msgname = type(r).__name__

        self.event_callback(msgname, r)

    def _control_ping(self, context):
        self._write(self.encode(self.control_ping_msgdef,
                        { '_vl_msg_id' : self.control_ping_index,
                          'context' : context}))

    def _call_vpp(self, i, msgdef, multipart, **kwargs):
        if not 'context' in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        self.results_prepare(context)
        self._write(b)

        if multipart:
            self.results[context]['m'] = True
            self._control_ping(context)
        self.results_wait(context)
        r = self.results[context]['r']
        self.results_clean(context)
        return r

    def _call_vpp_async(self, i, msgdef, multipart, **kwargs):
        if not 'context' in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i
        b = self.encode(msgdef, kwargs)

        self._write(b)

    def register_event_callback(self, callback):
        self.event_callback = callback

