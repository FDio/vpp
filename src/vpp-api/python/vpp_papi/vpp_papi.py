#!/usr/bin/env python3
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
from __future__ import absolute_import
import ctypes
import ipaddress
import sys
import multiprocessing as mp
import os
import queue
import logging
import functools
import json
import threading
import fnmatch
import weakref
import atexit
import time
from . vpp_format import verify_enum_hint
from . vpp_serializer import VPPType, VPPEnumType, VPPEnumFlagType, VPPUnionType
from . vpp_serializer import VPPMessage, vpp_get_type, VPPTypeAlias

try:
    import VppTransport
except ModuleNotFoundError:
    class V:
        """placeholder for VppTransport as the implementation is dependent on
        VPPAPIClient's initialization values
        """

    VppTransport = V

logger = logging.getLogger('vpp_papi')
logger.addHandler(logging.NullHandler())

__all__ = ('FuncWrapper', 'VPP', 'VppApiDynamicMethodHolder',
           'VppEnum', 'VppEnumType', 'VppEnumFlag',
           'VPPIOError', 'VPPRuntimeError', 'VPPValueError',
           'VPPApiClient', )


def metaclass(metaclass):
    @functools.wraps(metaclass)
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())

    return wrapper


class VppEnumType(type):
    def __getattr__(cls, name):
        t = vpp_get_type(name)
        return t.enum


@metaclass(VppEnumType)
class VppEnum:
    pass


@metaclass(VppEnumType)
class VppEnumFlag:
    pass


def vpp_atexit(vpp_weakref):
    """Clean up VPP connection on shutdown."""
    vpp_instance = vpp_weakref()
    if vpp_instance and vpp_instance.transport.connected:
        logger.debug('Cleaning up VPP on exit')
        vpp_instance.disconnect()


def add_convenience_methods():
    # provide convenience methods to IP[46]Address.vapi_af
    def _vapi_af(self):
        if 6 == self._version:
            return VppEnum.vl_api_address_family_t.ADDRESS_IP6.value
        if 4 == self._version:
            return VppEnum.vl_api_address_family_t.ADDRESS_IP4.value
        raise ValueError("Invalid _version.")

    def _vapi_af_name(self):
        if 6 == self._version:
            return 'ip6'
        if 4 == self._version:
            return 'ip4'
        raise ValueError("Invalid _version.")

    ipaddress._IPAddressBase.vapi_af = property(_vapi_af)
    ipaddress._IPAddressBase.vapi_af_name = property(_vapi_af_name)


class VppApiDynamicMethodHolder:
    pass


class FuncWrapper:
    def __init__(self, func):
        self._func = func
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __call__(self, **kwargs):
        return self._func(**kwargs)

    def __repr__(self):
        return '<FuncWrapper(func=<%s(%s)>)>' % (self.__name__, self.__doc__)


class VPPApiError(Exception):
    pass


class VPPNotImplementedError(NotImplementedError):
    pass


class VPPIOError(IOError):
    pass


class VPPRuntimeError(RuntimeError):
    pass


class VPPValueError(ValueError):
    pass


class VPPApiJSONFiles:
    @classmethod
    def find_api_dir(cls, dirs):
        """Attempt to find the best directory in which API definition
        files may reside. If the value VPP_API_DIR exists in the environment
        then it is first on the search list. If we're inside a recognized
        location in a VPP source tree (src/scripts and src/vpp-api/python)
        then entries from there to the likely locations in build-root are
        added. Finally the location used by system packages is added.

        :returns: A single directory name, or None if no such directory
            could be found.
        """

        # perhaps we're in the 'src/scripts' or 'src/vpp-api/python' dir;
        # in which case, plot a course to likely places in the src tree
        import __main__ as main
        if hasattr(main, '__file__'):
            # get the path of the calling script
            localdir = os.path.dirname(os.path.realpath(main.__file__))
        else:
            # use cwd if there is no calling script
            localdir = os.getcwd()
        localdir_s = localdir.split(os.path.sep)

        def dmatch(dir):
            """Match dir against right-hand components of the script dir"""
            d = dir.split('/')  # param 'dir' assumes a / separator
            length = len(d)
            return len(localdir_s) > length and localdir_s[-length:] == d

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

        # check the directories for existence; first one wins
        for dir in dirs:
            if os.path.isdir(dir):
                return dir

        return None

    @classmethod
    def find_api_files(cls, api_dir=None, patterns='*'):  # -> list
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
            api_dir = cls.find_api_dir([])
            if api_dir is None:
                raise VPPApiError("api_dir cannot be located")

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

    @classmethod
    def process_json_file(self, apidef_file):
        api = json.load(apidef_file)
        return self._process_json(api)

    @classmethod
    def process_json_str(self, json_str):
        api = json.loads(json_str)
        return self._process_json(api)

    @staticmethod
    def _process_json(api):  # -> Tuple[Dict, Dict]
        types = {}
        services = {}
        messages = {}
        try:
            for t in api['enums']:
                t[0] = 'vl_api_' + t[0] + '_t'
                types[t[0]] = {'type': 'enum', 'data': t}
        except KeyError:
            pass
        try:
            for t in api['enumflags']:
                t[0] = 'vl_api_' + t[0] + '_t'
                types[t[0]] = {'type': 'enum', 'data': t}
        except KeyError:
            pass
        try:
            for t in api['unions']:
                t[0] = 'vl_api_' + t[0] + '_t'
                types[t[0]] = {'type': 'union', 'data': t}
        except KeyError:
            pass

        try:
            for t in api['types']:
                t[0] = 'vl_api_' + t[0] + '_t'
                types[t[0]] = {'type': 'type', 'data': t}
        except KeyError:
            pass

        try:
            for t, v in api['aliases'].items():
                types['vl_api_' + t + '_t'] = {'type': 'alias', 'data': v}
        except KeyError:
            pass

        try:
            services.update(api['services'])
        except KeyError:
            pass

        i = 0
        while True:
            unresolved = {}
            for k, v in types.items():
                t = v['data']
                if not vpp_get_type(k):
                    if v['type'] == 'enum':
                        try:
                            VPPEnumType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                if not vpp_get_type(k):
                    if v['type'] == 'enumflag':
                        try:
                            VPPEnumFlagType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v['type'] == 'union':
                        try:
                            VPPUnionType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v['type'] == 'type':
                        try:
                            VPPType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v['type'] == 'alias':
                        try:
                            VPPTypeAlias(k, t)
                        except ValueError:
                            unresolved[k] = v
            if len(unresolved) == 0:
                break
            if i > 3:
                raise VPPValueError('Unresolved type definitions {}'
                                    .format(unresolved))
            types = unresolved
            i += 1
        try:
            for m in api['messages']:
                try:
                    messages[m[0]] = VPPMessage(m[0], m[1:])
                except VPPNotImplementedError:
                    ### OLE FIXME
                    logger.error('Not implemented error for {}'.format(m[0]))
        except KeyError:
            pass
        return messages, services


class VPPApiClient:
    """VPP interface.

    This class provides the APIs to VPP.  The APIs are loaded
    from provided .api.json files and makes functions accordingly.
    These functions are documented in the VPP .api files, as they
    are dynamically created.

    Additionally, VPP can send callback messages; this class
    provides a means to register a callback function to receive
    these messages in a background thread.
    """
    apidir = None
    VPPApiError = VPPApiError
    VPPRuntimeError = VPPRuntimeError
    VPPValueError = VPPValueError
    VPPNotImplementedError = VPPNotImplementedError
    VPPIOError = VPPIOError


    def __init__(self, apifiles=None, testmode=False, async_thread=True,
                 logger=None, loglevel=None,
                 read_timeout=5, use_socket=False,
                 server_address='/run/vpp/api.sock'):
        """Create a VPP API object.

        apifiles is a list of files containing API
        descriptions that will be loaded - methods will be
        dynamically created reflecting these APIs.  If not
        provided this will load the API files from VPP's
        default install location.

        logger, if supplied, is the logging logger object to log to.
        loglevel, if supplied, is the log level this logger is set
        to report at (from the loglevels in the logging module).
        """
        if logger is None:
            logger = logging.getLogger(
                "{}.{}".format(__name__, self.__class__.__name__))
            if loglevel is not None:
                logger.setLevel(loglevel)
        self.logger = logger

        self.messages = {}
        self.services = {}
        self.id_names = []
        self.id_msgdef = []
        self.header = VPPType('header', [['u16', 'msgid'],
                                         ['u32', 'client_index']])
        self.apifiles = []
        self.event_callback = None
        self.message_queue = queue.Queue()
        self.read_timeout = read_timeout
        self.async_thread = async_thread
        self.event_thread = None
        self.testmode = testmode
        self.use_socket = use_socket
        self.server_address = server_address
        self._apifiles = apifiles
        self.stats = {}

        if use_socket:
            from . vpp_transport_socket import VppTransport
        else:
            from . vpp_transport_shmem import VppTransport

        if not apifiles:
            # Pick up API definitions from default directory
            try:
                apifiles = VPPApiJSONFiles.find_api_files(self.apidir)
            except (RuntimeError, VPPApiError):
                # In test mode we don't care that we can't find the API files
                if testmode:
                    apifiles = []
                else:
                    raise VPPRuntimeError

        for file in apifiles:
            with open(file) as apidef_file:
                m, s = VPPApiJSONFiles.process_json_file(apidef_file)
                self.messages.update(m)
                self.services.update(s)

        self.apifiles = apifiles

        # Basic sanity check
        if len(self.messages) == 0 and not testmode:
            raise VPPValueError(1, 'Missing JSON message definitions')
        if not(verify_enum_hint(VppEnum.vl_api_address_family_t)):
            raise VPPRuntimeError("Invalid address family hints. "
                                  "Cannot continue.")

        self.transport = VppTransport(self, read_timeout=read_timeout,
                                      server_address=server_address)
        # Make sure we allow VPP to clean up the message rings.
        atexit.register(vpp_atexit, weakref.ref(self))

        add_convenience_methods()

    def get_function(self, name):
        return getattr(self._api, name)

    class ContextId:
        """Multiprocessing-safe provider of unique context IDs."""
        def __init__(self):
            self.context = mp.Value(ctypes.c_uint, 0)
            self.lock = mp.Lock()

        def __call__(self):
            """Get a new unique (or, at least, not recently used) context."""
            with self.lock:
                self.context.value += 1
                return self.context.value
    get_context = ContextId()

    def get_type(self, name):
        return vpp_get_type(name)

    @property
    def api(self):
        if not hasattr(self, "_api"):
            raise VPPApiError("Not connected, api definitions not available")
        return self._api

    def make_function(self, msg, i, multipart, do_async):
        if (do_async):
            def f(**kwargs):
                return self._call_vpp_async(i, msg, **kwargs)
        else:
            def f(**kwargs):
                return self._call_vpp(i, msg, multipart, **kwargs)

        f.__name__ = str(msg.name)
        f.__doc__ = ", ".join(["%s %s" %
                               (msg.fieldtypes[j], k)
                               for j, k in enumerate(msg.fields)])
        f.msg = msg

        return f

    def _register_functions(self, do_async=False):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        self._api = VppApiDynamicMethodHolder()
        for name, msg in self.messages.items():
            n = name + '_' + msg.crc[2:]
            i = self.transport.get_msg_index(n)
            if i > 0:
                self.id_msgdef[i] = msg
                self.id_names[i] = name

                # Create function for client side messages.
                if name in self.services:
                    f = self.make_function(msg, i, self.services[name], do_async)
                    setattr(self._api, name, FuncWrapper(f))
            else:
                self.logger.debug(
                    'No such message type or failed CRC checksum: %s', n)

    def connect_internal(self, name, msg_handler, chroot_prefix, rx_qlen,
                         do_async):
        pfx = chroot_prefix.encode('utf-8') if chroot_prefix else None

        rv = self.transport.connect(name, pfx,
                                    msg_handler, rx_qlen)
        if rv != 0:
            raise VPPIOError(2, 'Connect failed')
        self.vpp_dictionary_maxid = self.transport.msg_table_max_index()
        self._register_functions(do_async=do_async)

        # Initialise control ping
        crc = self.messages['control_ping'].crc
        self.control_ping_index = self.transport.get_msg_index(
            ('control_ping' + '_' + crc[2:]))
        self.control_ping_msgdef = self.messages['control_ping']
        if self.async_thread:
            self.event_thread = threading.Thread(
                target=self.thread_msg_handler)
            self.event_thread.daemon = True
            self.event_thread.start()
        else:
            self.event_thread = None
        return rv

    def connect(self, name, chroot_prefix=None, do_async=False, rx_qlen=32):
        """Attach to VPP.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        do_async - if true, messages are sent without waiting for a reply
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """
        msg_handler = self.transport.get_callback(do_async)
        return self.connect_internal(name, msg_handler, chroot_prefix, rx_qlen,
                                     do_async)

    def connect_sync(self, name, chroot_prefix=None, rx_qlen=32):
        """Attach to VPP in synchronous mode. Application must poll for events.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """

        return self.connect_internal(name, None, chroot_prefix, rx_qlen,
                                     do_async=False)

    def disconnect(self):
        """Detach from VPP."""
        rv = self.transport.disconnect()
        if self.event_thread is not None:
            self.message_queue.put("terminate event thread")
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

        if context == 0:
            # No context -> async notification that we feed to the callback
            self.message_queue.put_nowait(r)
        else:
            raise VPPIOError(2, 'RPC reply message received in event handler')

    def has_context(self, msg):
        if len(msg) < 10:
            return False

        header = VPPType('header_with_context', [['u16', 'msgid'],
                                                 ['u32', 'client_index'],
                                                 ['u32', 'context']])

        (i, ci, context), size = header.unpack(msg, 0)
        if self.id_names[i] == 'rx_thread_exit':
            return

        #
        # Decode message and returns a tuple.
        #
        msgobj = self.id_msgdef[i]
        if 'context' in msgobj.field_by_name and context >= 0:
            return True
        return False

    def decode_incoming_msg(self, msg, no_type_conversion=False):
        if not msg:
            logger.warning('vpp_api.read failed')
            return

        (i, ci), size = self.header.unpack(msg, 0)
        if self.id_names[i] == 'rx_thread_exit':
            return

        #
        # Decode message and returns a tuple.
        #
        msgobj = self.id_msgdef[i]
        if not msgobj:
            raise VPPIOError(2, 'Reply message undefined')

        r, size = msgobj.unpack(msg, ntc=no_type_conversion)
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

    def validate_args(self, msg, kwargs):
        d = set(kwargs.keys()) - set(msg.field_by_name.keys())
        if d:
            raise VPPValueError('Invalid argument {} to {}'
                                .format(list(d), msg.name))

    def _add_stat(self, name, ms):
        if not name in self.stats:
            self.stats[name] = {'max': ms, 'count': 1, 'avg': ms}
        else:
            if ms > self.stats[name]['max']:
                self.stats[name]['max'] = ms
            self.stats[name]['count'] += 1
            n = self.stats[name]['count']
            self.stats[name]['avg'] = self.stats[name]['avg'] * (n - 1) / n + ms / n

    def get_stats(self):
        s = '\n=== API PAPI STATISTICS ===\n'
        s += '{:<30} {:>4} {:>6} {:>6}\n'.format('message', 'cnt', 'avg', 'max')
        for n in sorted(self.stats.items(), key=lambda v: v[1]['avg'], reverse=True):
            s += '{:<30} {:>4} {:>6.2f} {:>6.2f}\n'.format(n[0], n[1]['count'],
                                                           n[1]['avg'], n[1]['max'])
        return s

    def _call_vpp(self, i, msgdef, service, **kwargs):
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
        ts = time.time()
        if 'context' not in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        kwargs['_vl_msg_id'] = i

        no_type_conversion = kwargs.pop('_no_type_conversion', False)
        timeout = kwargs.pop('_timeout', None)

        try:
            if self.transport.socket_index:
                kwargs['client_index'] = self.transport.socket_index
        except AttributeError:
            pass
        self.validate_args(msgdef, kwargs)

        s = 'Calling {}({})'.format(msgdef.name,
            ','.join(['{!r}:{!r}'.format(k, v) for k, v in kwargs.items()]))
        self.logger.debug(s)

        b = msgdef.pack(kwargs)
        self.transport.suspend()

        self.transport.write(b)

        msgreply = service['reply']
        stream = True if 'stream' in service else False
        if stream:
            if 'stream_msg' in service:
                # New service['reply'] = _reply and service['stream_message'] = _details
                stream_message = service['stream_msg']
                modern =True
            else:
                # Old  service['reply'] = _details
                stream_message = msgreply
                msgreply = 'control_ping_reply'
                modern = False
                # Send a ping after the request - we use its response
                # to detect that we have seen all results.
                self._control_ping(context)

        # Block until we get a reply.
        rl = []
        while (True):
            r = self.read_blocking(no_type_conversion, timeout)
            if r is None:
                raise VPPIOError(2, 'VPP API client: read failed')
            msgname = type(r).__name__
            if context not in r or r.context == 0 or context != r.context:
                # Message being queued
                self.message_queue.put_nowait(r)
                continue
            if msgname != msgreply and (stream and (msgname != stream_message)):
                print('REPLY MISMATCH', msgreply, msgname, stream_message, stream)
            if not stream:
                rl = r
                break
            if msgname == msgreply:
                if modern: # Return both reply and list
                    rl = r, rl
                break

            rl.append(r)

        self.transport.resume()

        s = 'Return value: {!r}'.format(r)
        if len(s) > 80:
            s = s[:80] + "..."
        self.logger.debug(s)
        te = time.time()
        self._add_stat(msgdef.name, (te - ts) * 1000)
        return rl

    def _call_vpp_async(self, i, msg, **kwargs):
        """Given a message, send the message and return the context.

        msgdef - the message packing definition
        i - the message type index
        context - context number - chosen at random if not
        supplied.
        The remainder of the kwargs are the arguments to the API call.

        The reply message(s) will be delivered later to the registered callback.
        The returned context will help with assigning which call
        the reply belongs to.
        """
        if 'context' not in kwargs:
            context = self.get_context()
            kwargs['context'] = context
        else:
            context = kwargs['context']
        try:
            if self.transport.socket_index:
                kwargs['client_index'] = self.transport.socket_index
        except AttributeError:
            kwargs['client_index'] = 0
        kwargs['_vl_msg_id'] = i
        b = msg.pack(kwargs)

        self.transport.write(b)
        return context

    def read_blocking(self, no_type_conversion=False, timeout=None):
        """Get next received message from transport within timeout, decoded.

        Note that notifications have context zero
        and are not put into receive queue (at least for socket transport),
        use async_thread with registered callback for processing them.

        If no message appears in the queue within timeout, return None.

        Optionally, type conversion can be skipped,
        as some of conversions are into less precise types.

        When r is the return value of this, the caller can get message name as:
            msgname = type(r).__name__
        and context number (type long) as:
            context = r.context

        :param no_type_conversion: If false, type conversions are applied.
        :type no_type_conversion: bool
        :returns: Decoded message, or None if no message (within timeout).
        :rtype: Whatever VPPType.unpack returns, depends on no_type_conversion.
        :raises VppTransportShmemIOError if timed out.
        """
        msg = self.transport.read(timeout=timeout)
        if not msg:
            return None
        return self.decode_incoming_msg(msg, no_type_conversion)

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
        """Python thread calling the user registered message handler.

        This is to emulate the old style event callback scheme. Modern
        clients should provide their own thread to poll the event
        queue.
        """
        while True:
            r = self.message_queue.get()
            if r == "terminate event thread":
                break
            msgname = type(r).__name__
            if self.event_callback:
                self.event_callback(msgname, r)

    def validate_message_table(self, namecrctable):
        """Take a dictionary of name_crc message names
        and returns an array of missing messages"""

        missing_table = []
        for name_crc in namecrctable:
            i = self.transport.get_msg_index(name_crc)
            if i <= 0:
                missing_table.append(name_crc)
        return missing_table

    def dump_message_table(self):
        """Return VPPs API message table as name_crc dictionary"""
        return self.transport.message_table

    def dump_message_table_filtered(self, msglist):
        """Return VPPs API message table as name_crc dictionary,
        filtered by message name list."""

        replies = [self.services[n]['reply'] for n in msglist]
        message_table_filtered = {}
        for name in msglist + replies:
            for k,v in self.transport.message_table.items():
                if k.startswith(name):
                    message_table_filtered[k] = v
                    break
        return message_table_filtered

    def __repr__(self):
        return "<VPPApiClient apifiles=%s, testmode=%s, async_thread=%s, " \
               "logger=%s, read_timeout=%s, use_socket=%s, " \
               "server_address='%s'>" % (
                   self._apifiles, self.testmode, self.async_thread,
                   self.logger, self.read_timeout, self.use_socket,
                   self.server_address)

    def details_iter(self, f, **kwargs):
        cursor = 0
        while True:
            kwargs['cursor'] = cursor
            rv, details = f(**kwargs)
            #
            # Convert to yield from details when we only support python 3
            #
            for d in details:
                yield d
            if rv.retval == 0 or rv.retval != -165:
                break
            cursor = rv.cursor

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
