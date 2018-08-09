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
from __future__ import absolute_import
import sys
import os
import logging
import collections
import struct
import json
import threading
import fnmatch
import weakref
import atexit
from cffi import FFI
import cffi
from . vpp_serializer import VPPType, VPPEnumType, VPPUnionType, BaseTypes
from . vpp_serializer import VPPMessage

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


def vpp_atexit(vpp_weakref):
    """Clean up VPP connection on shutdown."""
    vpp_instance = vpp_weakref()
    if vpp_instance.connected:
        vpp_instance.logger.debug('Cleaning up VPP on exit')
        vpp_instance.disconnect()


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


class VppApiDynamicMethodHolder(object):
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

    def process_json_file(self, apidef_file):
        api = json.load(apidef_file)
        types = {}
        for t in api['enums']:
            t[0] = 'vl_api_' + t[0] + '_t'
            types[t[0]] = {'type': 'enum', 'data': t}
        for t in api['unions']:
            t[0] = 'vl_api_' + t[0] + '_t'
            types[t[0]] = {'type': 'union', 'data': t}
        for t in api['types']:
            t[0] = 'vl_api_' + t[0] + '_t'
            types[t[0]] = {'type': 'type', 'data': t}

        i = 0
        while True:
            unresolved = {}
            for k, v in types.items():
                t = v['data']
                if v['type'] == 'enum':
                    try:
                        VPPEnumType(t[0], t[1:])
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
            if len(unresolved) == 0:
                break
            if i > 3:
                raise ValueError('Unresolved type definitions {}'
                                 .format(unresolved))
            types = unresolved
            i += 1

        for m in api['messages']:
            try:
                self.messages[m[0]] = VPPMessage(m[0], m[1:])
            except NotImplementedError:
                self.logger.error('Not implemented error for {}'.format(m[0]))

    def __init__(self, apifiles=None, testmode=False, async_thread=True,
                 logger=logging.getLogger('vpp_papi'), loglevel='debug',
                 read_timeout=0):
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
        global vpp_object
        vpp_object = self

        if logger is None:
            logger = logging.getLogger(__name__)
            if loglevel is not None:
                logger.setLevel(loglevel)
        self.logger = logger

        self.messages = {}
        self.id_names = []
        self.id_msgdef = []
        self.connected = False
        self.header = VPPType('header', [['u16', 'msgid'],
                                         ['u32', 'client_index']])
        self.apifiles = []
        self.event_callback = None
        self.message_queue = queue.Queue()
        self.read_timeout = read_timeout
        self.vpp_api = vpp_api
        self.async_thread = async_thread

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
                self.process_json_file(apidef_file)

        self.apifiles = apifiles

        # Basic sanity check
        if len(self.messages) == 0 and not testmode:
            raise ValueError(1, 'Missing JSON message definitions')

        # Make sure we allow VPP to clean up the message rings.
        atexit.register(vpp_atexit, weakref.ref(self))

        # Register error handler
        if not testmode:
            vpp_api.vac_set_error_handler(vac_error_handler)

        # Support legacy CFFI
        # from_buffer supported from 1.8.0
        (major, minor, patch) = [int(s) for s in
                                 cffi.__version__.split('.', 3)]
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

    @property
    def api(self):
        if not hasattr(self, "_api"):
            raise Exception("Not connected, api definitions not available")
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
        return f

    def _register_functions(self, do_async=False):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        self._api = VppApiDynamicMethodHolder()
        for name, msg in vpp_iterator(self.messages):
            n = name + '_' + msg.crc[2:]
            i = vpp_api.vac_get_msg_index(n.encode())
            if i > 0:
                self.id_msgdef[i] = msg
                self.id_names[i] = name
                # TODO: Fix multipart (use services)
                multipart = True if name.find('_dump') > 0 else False
                f = self.make_function(msg, i, multipart, do_async)
                setattr(self._api, name, FuncWrapper(f))
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
        return vpp_api.vac_write(bytes(buf), len(buf))

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
                         do_async):
        pfx = chroot_prefix.encode() if chroot_prefix else ffi.NULL
        rv = vpp_api.vac_connect(name.encode(), pfx, msg_handler, rx_qlen)
        if rv != 0:
            raise IOError(2, 'Connect failed')
        self.connected = True
        self.vpp_dictionary_maxid = vpp_api.vac_msg_table_max_index()
        self._register_functions(do_async=do_async)

        # Initialise control ping
        crc = self.messages['control_ping'].crc
        self.control_ping_index = vpp_api.vac_get_msg_index(
            ('control_ping' + '_' + crc[2:]).encode())
        self.control_ping_msgdef = self.messages['control_ping']
        if self.async_thread:
            self.event_thread = threading.Thread(
                target=self.thread_msg_handler)
            self.event_thread.daemon = True
            self.event_thread.start()
        return rv

    def connect(self, name, chroot_prefix=None, do_async=False, rx_qlen=32):
        """Attach to VPP.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        do_async - if true, messages are sent without waiting for a reply
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """
        msg_handler = vac_callback_sync if not do_async else vac_callback_async
        return self.connect_internal(name, msg_handler, chroot_prefix, rx_qlen,
                                     do_async)

    def connect_sync(self, name, chroot_prefix=None, rx_qlen=32):
        """Attach to VPP in synchronous mode. Application must poll for events.

        name - the name of the client.
        chroot_prefix - if VPP is chroot'ed, the prefix of the jail
        rx_qlen - the length of the VPP message receive queue between
        client and server.
        """

        return self.connect_internal(name, ffi.NULL, chroot_prefix, rx_qlen,
                                     do_async=False)

    def disconnect(self):
        """Detach from VPP."""
        rv = vpp_api.vac_disconnect()
        self.connected = False
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
            raise IOError(2, 'RPC reply message received in event handler')

    def decode_incoming_msg(self, msg):
        if not msg:
            self.logger.warning('vpp_api.read failed')
            return

        i, ci = self.header.unpack(msg, 0)
        if self.id_names[i] == 'rx_thread_exit':
            return

        #
        # Decode message and returns a tuple.
        #
        msgobj = self.id_msgdef[i]
        if not msgobj:
            raise IOError(2, 'Reply message undefined')

        r = msgobj.unpack(msg)

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
            raise ValueError('Invalid argument {} to {}'
                             .format(list(d), msg.name))

    def _call_vpp(self, i, msg, multipart, **kwargs):
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

        self.validate_args(msg, kwargs)
        b = msg.pack(kwargs)
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

    def _call_vpp_async(self, i, msg, **kwargs):
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
        kwargs['client_index'] = 0
        kwargs['_vl_msg_id'] = i
        b = msg.pack(kwargs)

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
            if r == "terminate event thread":
                break
            msgname = type(r).__name__
            if self.event_callback:
                self.event_callback(msgname, r)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
