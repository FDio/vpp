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

from __future__ import absolute_import
import ipaddress
import logging
import functools
import json
import weakref
import atexit
import importlib.resources as resources
import struct
import asyncio

from .vpp_serializer import VPPType, VPPEnumType, VPPEnumFlagType, VPPUnionType
from .vpp_serializer import VPPMessage, vpp_get_type, VPPTypeAlias

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__all__ = (
    "FuncWrapper",
    "VppApiDynamicMethodHolder",
    "VppEnum",
    "VppEnumType",
    "VppEnumFlag",
    "VPPIOError",
    "VPPRuntimeError",
    "VPPValueError",
    "VPPApiClient",
)


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


class QueueObject:
    def __init__(self, b, context, future=None, eof_stream=None, details=None):
        self.b = b
        self.context = context
        self.future = future
        self.eof_stream = eof_stream
        self.details_msg = details


def vpp_atexit(vpp_weakref):
    """Clean up VPP connection on shutdown."""
    vpp_instance = vpp_weakref()
    if vpp_instance and vpp_instance.connected:
        logger.debug("Cleaning up VPP on exit")
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
            return "ip6"
        if 4 == self._version:
            return "ip4"
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
        return "<FuncWrapper(func=<%s(%s)>)>" % (self.__name__, self.__doc__)


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
    def process_json_str(self, json_str):
        api = json.loads(json_str)
        return self._process_json(api)

    @classmethod
    def process_json_array_str(self, json_str):
        services = {}
        messages = {}

        apis = json.loads(json_str)
        for a in apis:
            m, s = self._process_json(a)
            messages.update(m)
            services.update(s)
        return messages, services

    @staticmethod
    def _process_json(api):  # -> Tuple[Dict, Dict]
        types = {}
        services = {}
        messages = {}
        try:
            for t in api["enums"]:
                t[0] = "vl_api_" + t[0] + "_t"
                types[t[0]] = {"type": "enum", "data": t}
        except KeyError:
            pass
        try:
            for t in api["enumflags"]:
                t[0] = "vl_api_" + t[0] + "_t"
                types[t[0]] = {"type": "enum", "data": t}
        except KeyError:
            pass
        try:
            for t in api["unions"]:
                t[0] = "vl_api_" + t[0] + "_t"
                types[t[0]] = {"type": "union", "data": t}
        except KeyError:
            pass

        try:
            for t in api["types"]:
                t[0] = "vl_api_" + t[0] + "_t"
                types[t[0]] = {"type": "type", "data": t}
        except KeyError:
            pass

        try:
            for t, v in api["aliases"].items():
                types["vl_api_" + t + "_t"] = {"type": "alias", "data": v}
        except KeyError:
            pass

        try:
            services.update(api["services"])
        except KeyError:
            pass

        i = 0
        while True:
            unresolved = {}
            for k, v in types.items():
                t = v["data"]
                if not vpp_get_type(k):
                    if v["type"] == "enum":
                        try:
                            VPPEnumType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                if not vpp_get_type(k):
                    if v["type"] == "enumflag":
                        try:
                            VPPEnumFlagType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v["type"] == "union":
                        try:
                            VPPUnionType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v["type"] == "type":
                        try:
                            VPPType(t[0], t[1:])
                        except ValueError:
                            unresolved[k] = v
                    elif v["type"] == "alias":
                        try:
                            VPPTypeAlias(k, t)
                        except ValueError:
                            unresolved[k] = v
            if len(unresolved) == 0:
                break
            if i > 3:
                raise VPPValueError("Unresolved type definitions {}".format(unresolved))
            types = unresolved
            i += 1
        try:
            for m in api["messages"]:
                try:
                    messages[m[0]] = VPPMessage(m[0], m[1:])
                except VPPNotImplementedError:
                    logger.error("Not implemented error for {}".format(m[0]))
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

    VPPApiError = VPPApiError
    VPPRuntimeError = VPPRuntimeError
    VPPValueError = VPPValueError
    VPPNotImplementedError = VPPNotImplementedError
    VPPIOError = VPPIOError

    def __init__(
        self,
        *,
        testmode=False,
        logger=None,
        loglevel=None,
        read_timeout=5,
        server_address="/run/vpp/api.sock",
    ):
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
                "{}.{}".format(__name__, self.__class__.__name__)
            )
            if loglevel is not None:
                logger.setLevel(loglevel)
        self.logger = logger

        self.messages = {}
        self.services = {}
        self.id_names = []
        self.id_msgdef = []
        self.header = VPPType("header", [["u16", "msgid"], ["u32", "client_index"]])
        self.message_queue = asyncio.Queue()
        self.read_timeout = read_timeout
        self.testmode = testmode
        self.server_address = server_address
        self.stats = {}
        self.connected = False
        self.message_table = {}
        self.header_struct = struct.Struct(">QII")

        # Bootstrap the API (memclnt.api bundled with VPP PAPI)
        with resources.open_text("vpp_papi.data", "memclnt.api.json") as f:
            resource_content = f.read()
        self.messages, self.services = VPPApiJSONFiles.process_json_str(
            resource_content
        )

        # Basic sanity check
        if len(self.messages) == 0 and not testmode:
            raise VPPValueError(1, "Missing JSON message definitions")

        # Make sure we allow VPP to clean up the message rings.
        atexit.register(vpp_atexit, weakref.ref(self))

        add_convenience_methods()

    def get_function(self, name):
        return getattr(self._api, name)

    class ContextId:
        """Multiprocessing-safe provider of unique context IDs."""

        def __init__(self):
            self.context = 0

        def __call__(self):
            """Get a new unique (or, at least, not recently used) context."""
            self.context += 1
            return self.context

    get_context = ContextId()

    def get_type(self, name):
        return vpp_get_type(name)

    @property
    def api(self):
        if not hasattr(self, "_api"):
            raise VPPApiError("Not connected, api definitions not available")
        return self._api

    def make_function(self, msg, i, multipart):
        def f(**kwargs):
            return self._call_vpp_async(i, msg, multipart, **kwargs)

        f.__name__ = str(msg.name)
        f.__doc__ = ", ".join(
            ["%s %s" % (msg.fieldtypes[j], k) for j, k in enumerate(msg.fields)]
        )
        f.msg = msg

        return f

    def make_pack_function(self, msg, i, multipart):
        def f(**kwargs):
            return self._call_vpp_pack(i, msg, **kwargs)

        f.msg = msg
        return f

    def _register_functions(self):
        self.id_names = [None] * (self.vpp_dictionary_maxid + 1)
        self.id_msgdef = [None] * (self.vpp_dictionary_maxid + 1)
        self._api = VppApiDynamicMethodHolder()
        for name, msg in self.messages.items():
            n = name + "_" + msg.crc[2:]
            i = self.message_table[n]
            if i > 0:
                self.id_msgdef[i] = msg
                self.id_names[i] = name

                # Create function for client side messages.
                if name in self.services:
                    f = self.make_function(msg, i, self.services[name])
                    f_pack = self.make_pack_function(msg, i, self.services[name])
                    setattr(self._api, name, FuncWrapper(f))
                    setattr(self._api, name + "_pack", FuncWrapper(f_pack))
            else:
                self.logger.debug("No such message type or failed CRC checksum: %s", n)

    async def get_api_definitions(self):
        """get_api_definition. Bootstrap from the embedded memclnt.api.json file."""

        # Bootstrap so we can call the get_api_json function
        self._register_functions()

        # f = await self.api.get_api_json()
        f = self.api.get_api_json()
        r = await asyncio.gather(f)
        r = r[0]
        if r.retval != 0:
            raise VPPApiError("Failed to load API definitions from VPP")

        # Process JSON
        m, s = VPPApiJSONFiles.process_json_array_str(r.json)
        self.messages.update(m)
        self.services.update(s)

    def get_msg_index(self, name):
        try:
            return self.message_table[name]
        except KeyError:
            return 0

    async def connect(self, name, event_queue):
        """Attach to VPP."""
        try:
            reader, writer = await asyncio.open_unix_connection(self.server_address)
        except (PermissionError, FileNotFoundError):
            return -1
        self.reader = reader
        self.writer = writer

        # Initialise sockclnt_create
        sockclnt_create = self.messages["sockclnt_create"]
        sockclnt_create_reply = self.messages["sockclnt_create_reply"]

        args = {"_vl_msg_id": 15, "name": name, "context": 124}
        b = sockclnt_create.pack(args)
        # Send header
        hdr = self.header_struct.pack(0, len(b), 0)
        writer.write(hdr)
        writer.write(b)
        await writer.drain()
        hdr = await reader.readexactly(16)
        (_, hdrlen, _) = self.header_struct.unpack(hdr)  # If at head of message
        msg = await reader.readexactly(hdrlen)
        header2 = VPPType("header", [["u16", "msgid"], ["u32", "client_index"]])
        hdr, _ = header2.unpack(msg, 0)
        if hdr.msgid != 16:
            # TODO: Add first numeric argument.
            raise IOError("Invalid reply message")

        r, length = sockclnt_create_reply.unpack(msg)
        self.socket_index = r.index
        for m in r.message_table:
            n = m.name
            self.message_table[n] = m.index
        # Find the maximum index of the message table
        self.vpp_dictionary_maxid = max(self.message_table.values() or [0])

        # self.worker_task = asyncio.create_task(self.message_handler(event_queue))
        requests = {}
        self.queue_task = asyncio.create_task(self.queue_worker(requests))
        self.socket_task = asyncio.create_task(
            self.socket_reader(requests, event_queue)
        )

        # Register the functions we have (memclnt.json)
        await self.get_api_definitions()

        self._register_functions()

        # Initialise control ping
        crc = self.messages["control_ping"].crc
        self.control_ping_index = self.get_msg_index(("control_ping" + "_" + crc[2:]))
        self.control_ping_msgdef = self.messages["control_ping"]

        return 0

    async def disconnect(self):
        """Detach from VPP."""

        rv = 0
        try:
            # Might fail, if VPP closes socket before packet makes it out,
            # or if there was a failure during connect().
            rv = await self.api.sockclnt_delete(index=self.socket_index)
        except IOError:
            pass
        self.connected = False
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

        await self.message_queue.put(None)  # Send sentinel to stop the event processor
        await asyncio.gather(self.queue_task)  # Wait for them to finish

        self.socket_task.cancel()

        # Wipe message table, VPP can be restarted with different plugins.
        self.message_table = {}
        # Collect garbage.
        # Queues will be collected after connect replaces them.
        return rv

    def has_context(self, msg):
        if len(msg) < 10:
            return False

        header = VPPType(
            "header_with_context",
            [["u16", "msgid"], ["u32", "client_index"], ["u32", "context"]],
        )

        (i, ci, context), size = header.unpack(msg, 0)

        if self.id_names[i] == "rx_thread_exit":
            return

        #
        # Decode message and returns a tuple.
        #
        msgobj = self.id_msgdef[i]
        if "context" in msgobj.field_by_name and context >= 0:
            return True
        return False

    def decode_incoming_msg(self, msg, no_type_conversion=False):
        if not msg:
            logger.warning("vpp_api.read failed")
            return

        (i, ci), size = self.header.unpack(msg, 0)
        if self.id_names[i] == "rx_thread_exit":
            return

        #
        # Decode message and returns a tuple.
        #
        msgobj = self.id_msgdef[i]
        if not msgobj:
            raise VPPIOError(2, "Reply message undefined")

        r, size = msgobj.unpack(msg, ntc=no_type_conversion)
        return r

    def _control_ping(self, context):
        """Send a ping command."""
        args = {
            "_vl_msg_id": self.control_ping_index,
            "client_index": self.socket_index,
            "context": context,
        }
        # args['context'] = context
        # TODO: Cache packed version.
        b = self.control_ping_msgdef.pack(args)
        self.message_queue.put_nowait(QueueObject(b, context))

    def validate_args(self, msg, kwargs):
        d = set(kwargs.keys()) - set(msg.field_by_name.keys())
        if d:
            raise VPPValueError("Invalid argument {} to {}".format(list(d), msg.name))

    def _add_stat(self, name, ms):
        if name not in self.stats:
            self.stats[name] = {"max": ms, "count": 1, "avg": ms}
        else:
            if ms > self.stats[name]["max"]:
                self.stats[name]["max"] = ms
            self.stats[name]["count"] += 1
            n = self.stats[name]["count"]
            self.stats[name]["avg"] = self.stats[name]["avg"] * (n - 1) / n + ms / n

    def get_stats(self):
        s = "\n=== API PAPI STATISTICS ===\n"
        s += "{:<30} {:>4} {:>6} {:>6}\n".format("message", "cnt", "avg", "max")
        for n in sorted(self.stats.items(), key=lambda v: v[1]["avg"], reverse=True):
            s += "{:<30} {:>4} {:>6.2f} {:>6.2f}\n".format(
                n[0], n[1]["count"], n[1]["avg"], n[1]["max"]
            )
        return s

    def get_field_options(self, msg, fld_name):
        # when there is an option, the msgdef has 3 elements.
        # ['u32', 'ring_size', {'default': 1024}]
        for _def in self.messages[msg].msgdef:
            if isinstance(_def, list) and len(_def) == 3 and _def[1] == fld_name:
                return _def[2]

    async def queue_worker(self, requests):
        """Process items from an asyncio.Queue."""
        queue = self.message_queue
        while True:
            item = await queue.get()
            if item is None:  # Stop signal
                logger.debug("Stopping queue worker...")
                return
            if item.context not in requests:
                requests[item.context] = (
                    item.future,
                    item.details_msg,
                    item.eof_stream,
                    [],
                )
            await self._write(item.b)
            queue.task_done()

    async def socket_reader(self, requests, event_queue):
        """Read data from the socket asynchronously and match requests."""
        while True:
            try:
                # Await a line of data from the socket
                item = await self._read()
                if not item:
                    logger.error("Socket closed.")
                    break

                # self.message_queue.task_done()
                msgname = type(item).__name__
                logger.debug(f"socket reader: {msgname} {item.context}")
                try:
                    req = requests[item.context]
                    if req[1]:  # stream
                        logger.debug(f"Streaming message {msgname}: {req[1]} {req[2]}")
                        if msgname == req[1]:
                            req[0].set_result((item, req[3]))
                            del requests[item.context]
                            continue
                        elif msgname == req[2] or req[2] is None:
                            req[3].append(item)
                        else:
                            raise VPPIOError(1, f"Unexpected message {msgname}")
                    else:
                        req[0].set_result(item)
                        del requests[item.context]
                except Exception as e:
                    # Add to event queue
                    logger.debug("Adding {msgname} to event queue")
                    event_queue.put_nowait(item)
            except asyncio.CancelledError:
                break

    def _call_vpp_async(self, i, msgdef, service, **kwargs):
        if "context" not in kwargs:
            context = self.get_context()
            kwargs["context"] = context
        else:
            context = kwargs["context"]
        try:
            if self.socket_index:
                kwargs["client_index"] = self.socket_index
        except AttributeError:
            kwargs["client_index"] = 0
        kwargs["_vl_msg_id"] = i

        self.validate_args(msgdef, kwargs)
        b = msgdef.pack(kwargs)
        response_future = asyncio.Future()
        stream_message = service["stream_msg"] if "stream_msg" in service else None
        try:
            if service["stream"]:
                if stream_message is None:
                    eof_stream = "control_ping_reply"
                    control_ping = True
                else:
                    eof_stream = service["reply"]
                    control_ping = False
        except KeyError:
            eof_stream = stream_message = None
            control_ping = False

        self.message_queue.put_nowait(
            QueueObject(b, context, response_future, stream_message, eof_stream)
        )
        if control_ping:
            self._control_ping(context=context)

        # await self.message_queue.put_(QueueObject(b, context, response_future))
        # return await response_future
        return response_future

    def _call_vpp_pack(self, i, msg, **kwargs):
        """Given a message, return the binary representation."""
        kwargs["_vl_msg_id"] = i
        kwargs["client_index"] = 0
        kwargs["context"] = 0
        return msg.pack(kwargs)

    async def _write(self, b):
        """Send a binary-packed message to VPP."""
        hdr = self.header_struct.pack(0, len(b), 0)
        self.writer.write(hdr)
        self.writer.write(b)
        await self.writer.drain()

    async def _read(self, timeout=5, no_type_conversion=False):
        """Read single complete message, return it or empty on error."""
        hdr = await self.reader.readexactly(16)
        if not hdr:
            return
        (_, hdrlen, _) = self.header_struct.unpack(hdr)  # If at head of message

        # Read the rest of the message
        msg = await self._read_exactly(hdrlen)
        if hdrlen == len(msg):
            return self.decode_incoming_msg(msg, no_type_conversion)
        raise IOError(1, f"Unknown socket read error, read {len(msg)} bytes")

    async def _read_exactly(self, n):
        """Read exactly n bytes from the reader."""
        data = bytearray()
        while len(data) < n:
            packet = await self.reader.readexactly(n - len(data))
            if not packet:
                raise IOError(
                    1, f"Unexpected end of stream, read {len(data)} bytes out of {n}"
                )
            data.extend(packet)
        return bytes(data)

    def validate_message_table(self, namecrctable):
        """Take a dictionary of name_crc message names
        and returns an array of missing messages"""

        missing_table = []
        for name_crc in namecrctable:
            i = self.get_msg_index(name_crc)
            if i <= 0:
                missing_table.append(name_crc)
        return missing_table

    def dump_message_table(self):
        """Return VPPs API message table as name_crc dictionary"""
        return self.message_table

    def dump_message_table_filtered(self, msglist):
        """Return VPPs API message table as name_crc dictionary,
        filtered by message name list."""

        replies = [self.services[n]["reply"] for n in msglist]
        message_table_filtered = {}
        for name in msglist + replies:
            for k, v in self.message_table.items():
                if k.startswith(name):
                    message_table_filtered[k] = v
                    break
        return message_table_filtered

    def __repr__(self):
        return (
            "<VPPApiClient apifiles=%s, testmode=%s, async_thread=%s, "
            "logger=%s, read_timeout=%s, "
            "server_address='%s'>"
            % (
                self._apifiles,
                self.testmode,
                self.async_thread,
                self.logger,
                self.read_timeout,
                self.server_address,
            )
        )

    def details_iter(self, f, **kwargs):
        cursor = 0
        while True:
            kwargs["cursor"] = cursor
            rv, details = f(**kwargs)
            for d in details:
                yield d
            if rv.retval == 0 or rv.retval != -165:
                break
            cursor = rv.cursor
