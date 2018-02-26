#!/usr/bin/env python2
#
# Copyright (c) 2018 Cisco and/or its affiliates.
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

import json
import pprint
from collections import OrderedDict


def underscore_to_camelcase_upper(name):
    return name.title().replace("_", "")


def underscore_to_camelcase_lower(name):
    name = name.title().replace("_", "")
    return name[0].lower() + name[1:]


class ParseException(Exception):
    pass


class Type(object):
    def __init__(self, name, is_swap_needed=True):
        self.name = name
        self.java_name = underscore_to_camelcase_upper(name)
        self.is_swap_needed = is_swap_needed


class SimpleType(Type):
    def __init__(self, name, java_name, jni_signature, jni_type, jni_accessor, is_swap_needed=True,
                 host_to_net_function=None, net_to_host_function=None):
        super(SimpleType, self).__init__(name, is_swap_needed)
        self.java_name = java_name
        self.jni_signature = jni_signature
        self.jni_type = jni_type
        self.jni_accessor = jni_accessor
        if is_swap_needed and (not host_to_net_function or not net_to_host_function):
            raise TypeError("Initialization of SimpleType(%s) failed: missing host_to_net_function and net_to_host_function", name)
        self.host_to_net_function = host_to_net_function
        self.net_to_host_function = net_to_host_function

    def __str__(self):
        return "SimpleType{name:%s, java_name:%s}" % (self.name, self.java_name)


_ARRAY_SUFFIX = '[]'


class Array(Type):
    def __init__(self, base_type):
        super(Array, self).__init__(base_type.name + _ARRAY_SUFFIX, base_type.is_swap_needed)
        self.java_name = base_type.java_name + _ARRAY_SUFFIX
        self.jni_signature = "[%s" % base_type.jni_signature
        self.jni_type = "%sArray" % base_type.jni_type
        self.jni_accessor = "ObjectField"
        self.jni_base_type = "j%s" % base_type.java_name
        self.host_to_net_function = base_type.host_to_net_function
        self.net_to_host_function = base_type.net_to_host_function
        # todo only these should be array specific members:
        self.base_type_name = base_type.name
        self.base_type_java_name = base_type.java_name.title()

    def __str__(self):
        return "Array{name:%s, java_name:%s}" % (self.name, self.java_name)


class Class(Type):
    def __init__(self, name, crc, fields, definition):
        super(Class, self).__init__(name, is_swap_needed=True)
        self.crc = crc
        self.fields = fields
        self.doc = _message_to_javadoc(definition) # todo rename _message_to_javadoc


# todo: consistency:
# 1) do not produce flat structure here and then have representation for each item that is produced (dto, callbackX, ...)
# 2) do produce flat structure
# 3) something in the middle: start with flat structure, then decide if it should be deflaten a bit
# todo: split java specific stuff from the actual model
# todo: reuse Klement's parser? (what about services?),
# todo: run Klements parser once?

class Field(object):
    def __init__(self, name, field_type, array_len=None, array_len_field=None):
        self.name = name
        self.java_name = underscore_to_camelcase_lower(name)
        self.type = field_type
        self.array_len = array_len
        self.array_len_field = array_len_field

    def __str__(self):
        return "Field{name:%s, java_name:%s, type:%s}" % (self.name, self.java_name, self.type)


def _message_to_javadoc(message_definition):
    """ Converts JSON message definition to javadoc """
    formatted_message = pprint.pformat(message_definition, indent=4, width=120, depth=None)
    return " * " + formatted_message.replace("\n", "\n * ")


# fixme use optional parameters instead of subclasses,
# it will translate to potentially faster code, e.g.
# msg.request = None
# (...)
# if msg.request:
#     (...)
# rather than:
# if hasattr(msg, 'request'):
class Message(object):
    def __init__(self, name, crc, fields, definition):
        self.name = name
        self.java_name_upper = underscore_to_camelcase_upper(name)
        self.java_name_lower = underscore_to_camelcase_lower(name)
        self.crc = crc[2:]
        self.fields = fields

        # todo perhasp instead having many fields here add another layer of models per feature (dtos, types, jvpp, jni, future, ...)
        # todo visitor pattern?
        self.has_fields = fields != []
        # todo consider using onyl definiton as argument and move whole paring logic here
        # todo consider unsing definition for eq and hash
        self.doc = _message_to_javadoc(definition)

    def __str__(self):
        return "Message{name:%s, java_name:%s, crc:%s, fields:%s}" % (
            self.name, self.java_name_upper, self.crc, self.fields)
        # return "[%s]" % "], [".join([str(f) for f in self.fields])

        # todo remove eq and hash before push (they are usied in tests only)
        # def __eq__(self, other):
        #     return (self.__class__ == other.__class__ and
        #             self.name == other.name and
        #             self.java_name_upper == other.java_name and
        #             self.crc == other.crc and
        #             self.fields == other.fields
        #             )
        #
        # def __hash__(self):
        #     return hash((self.name, self.java_name_upper, self.crc, self.fields))


# todo unify is_XXX function with model._is_XX versions
def is_request(msg):
    return hasattr(msg, 'reply')


def is_reply(msg):
    return hasattr(msg, 'request')


def is_dump(msg):
    return hasattr(msg, 'details')


def is_details(msg):
    return hasattr(msg, 'dump')


class Event(Message):
    def __init__(self, name, crc, fields, definition):
        super(Event, self).__init__(name, crc, fields, definition)


class Request(Message):
    def __init__(self, name, reply, crc, fields, definition):
        super(Request, self).__init__(name, crc, fields, definition)
        self.reply = reply
        self.reply_java = underscore_to_camelcase_upper(reply)

    def __str__(self):
        return "Request{name:%s, reply:%s, crc:%s, fields:%s}" % (self.name, self.reply, self.crc, self.fields)


class Reply(Message):
    def __init__(self, name, request, crc, fields, definition):
        super(Reply, self).__init__(name, crc, fields, definition)
        self.request = request
        self.request_java = underscore_to_camelcase_upper(request)

    def __str__(self):
        return "Reply{name:%s, request:%s, crc:%s, fields:%s}" % (self.name, self.request, self.crc, self.fields)


class Dump(Message):
    def __init__(self, name, details, crc, fields, definition):
        super(Dump, self).__init__(name, crc, fields, definition)
        self.details = details

    def __str__(self):
        return "Dump{name:%s, details:%s, crc:%s, fields:%s}" % (self.name, self.details, self.crc, self.fields)


class Details(Message):
    def __init__(self, name, dump, crc, fields, definition):
        super(Details, self).__init__(name, crc, fields, definition)
        self.dump = dump
        self.request_java = underscore_to_camelcase_upper(dump)

    def __str__(self):
        return "Details{name:%s, dump:%s, crc:%s, fields:%s}" % (self.name, self.dump, self.crc, self.fields)


BASE_PACKAGE = "io.fd.vpp.jvpp"


def _is_crc(item):
    """ Check whether the item inside message definition is just crc """
    return type(item) == dict and 'crc' in item


def _is_stream(service):
    return "stream" in service


def _is_reply_field(field):
    # Skip fields that are hidden to the jvpp user:
    # _vl_msg_id is handled at JNI layer,
    # Unlike in the request case, context is visible to allow matching replies with requests at Java layer.
    return field.name not in {'_vl_msg_id'}


def is_retval(field):
    return field.name == u'retval'


def _is_request_field(field):
    # Skip fields that are hidden to the jvpp user (handled by JNI layer)
    return field.name not in {'_vl_msg_id', 'client_index', 'context'}


# todo consistent element parsing (e.g. all methods in JsonParser)
# or static
# or group methods in classes (e.g. field parsing in field class)


def is_control_ping(msg):
    return msg.name == u'control_ping'


def is_control_ping_reply(msg):
    return msg.name == u'control_ping_reply'


def is_array(field):
    return field.array_len is not None


def _is_array(type_definition):
    return len(type_definition) > 2

# todo rename to json API
class JsonParser(object):
    def __init__(self, logger, json_api_files, plugin_name):
        self.logger = logger
        self.json_api_files = json_api_files  # todo provide json_file_by_definition map to improve javadoc
        self.plugin_package = BASE_PACKAGE + "." + plugin_name
        self.plugin_name = plugin_name
        self.plugin_java_name = underscore_to_camelcase_upper(plugin_name)
        self._load_json_files(json_api_files)
        self._parse_types()
        self._parse_services()
        self._parse_messages()
        self._validate_messages()

    def _load_json_files(self, json_api_files):
        self._enums = []
        self._types = []
        self._json_messages = [] # todo rename to _messages
        self._services = {}
        for file_name in json_api_files:
            with open(file_name) as f:
                j = json.load(f)
                self._enums.extend(j['enums'])
                self._types.extend(j['types'])
                self._json_messages.extend(j['messages'])
                self._services.update(j['services'])

    def _parse_types(self):
        # Mapping according to:
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
        # and
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#Get_type_Field_routines
        #
        # Unsigned types are converted to signed java types that have the same size.
        # It is the API user responsibility to interpret them correctly.

        self._types_by_name = OrderedDict({
            'u8': SimpleType('u8', 'byte', 'B', 'jbyte', 'ByteField', is_swap_needed=False),
            'i8': SimpleType('i8', 'byte', 'B', 'jbyte', 'ByteField', is_swap_needed=False),
            'u16': SimpleType('u16', 'short', 'S', 'jshort', 'ShortField',
                              host_to_net_function='clib_host_to_net_u16',
                              net_to_host_function='clib_net_to_host_u16'),
            'i16': SimpleType('i16', 'short', 'S', 'jshort', 'ShortField',
                              host_to_net_function='clib_host_to_net_i16',
                              net_to_host_function='clib_net_to_host_i16'),
            'u32': SimpleType('u32', 'int', 'I', 'jint', 'IntField',
                              host_to_net_function='clib_host_to_net_u32',
                              net_to_host_function='clib_net_to_host_u32'),
            'i32': SimpleType('i32', 'int', 'I', 'jint', 'IntField',
                              host_to_net_function='clib_host_to_net_i32',
                              net_to_host_function='clib_net_to_host_i32'),
            'u64': SimpleType('u64', 'long', 'J', 'jlong', 'LongField',
                              host_to_net_function='clib_host_to_net_u64',
                              net_to_host_function='clib_net_to_host_u64'),
            'i64': SimpleType('i64', 'long', 'J', 'jlong', 'LongField',
                              host_to_net_function='clib_host_to_net_i64',
                              net_to_host_function='clib_net_to_host_i64'),
            'f64': SimpleType('f64', 'double', 'D', 'jdouble', 'DoubleField', is_swap_needed=False)
        })

        for n, t in self._types_by_name.items():
            self._types_by_name[n + _ARRAY_SUFFIX] = Array(t)
        for json_type in self._types:
            name = json_type[0]
            definition = json_type[1:]
            self.logger.debug("Parsing type %s: %s", name, definition)
            self._types_by_name[name] = self._parse_type(name, definition)

        self.types = self._types_by_name.values()

    def _parse_type(self, name, definition):
        self.logger.debug("Parsing type %s: %s", name, definition)
        crc = None
        fields = []
        # todo: code repetition
        for item in definition:
            if _is_crc(item):
                crc = item['crc']
            elif item[0] in self._types_by_name and not _is_array(item):
                fields.append(Field(item[1], self._types_by_name[item[0]]))
            elif item[0] in self._types_by_name and _is_array(item):
                array_len_field = None
                if len(item) == 4:
                    for f in fields:
                        if f.name == item[3]:
                            array_len_field = f
                    if not array_len_field:
                        raise ParseException("Could not find field %s declared as length of array %s", item[3], item[1])
                fields.append(Field(item[1], self._types_by_name[item[0]+'[]'], item[2], array_len_field))
            else:
                raise ParseException("Unknown field type %s" % item)
        if not crc:
            raise ParseException("CRC was not defined for type %s" % definition)
        return Class(name, crc, fields, definition)

    def _parse_services(self):
        self._dumps_by_details = {}
        self._requests_by_reply = {}
        for name, service in self._services.iteritems():
            if _is_stream(service):
                self._dumps_by_details[service['reply']] = name
            else:
                self._requests_by_reply[service['reply']] = name

    def _parse_messages(self):
        # Preserve ordering from JSON file to make debugging easier.
        self._messages_by_name = OrderedDict()
        for json_msg in self._json_messages:
            try:
                name = json_msg[0]
                definition = json_msg[1:]
                self._messages_by_name[name] = self._parse_message(name, definition)
            except ParseException as e:
                self.logger.warning("Failed to parse message %s: %s. Skipping message.", name, e)

    def _parse_message(self, name, definition):
        self.logger.debug("Parsing message %s: %s", name, definition)
        crc = None
        fields = []
        for item in definition:
            if _is_crc(item):
                crc = item['crc']
            elif item[0] in self._types_by_name and not _is_array(item):
                fields.append(Field(item[1], self._types_by_name[item[0]]))
            elif item[0] in self._types_by_name and _is_array(item):
                array_len_field = None
                if len(item) == 4:
                    for f in fields:
                        if f.name == item[3]:
                            array_len_field = f
                    if not array_len_field:
                        raise ParseException("Could not find field %s declared as length of array %s", item[3], item[1])
                fields.append(Field(item[1], self._types_by_name[item[0]+'[]'], item[2], array_len_field)) #todo check array of length 0 special case
            else:
                raise ParseException("Unknown field type %s" % item)
        if not crc:
            raise ParseException("CRC was not defined for message %s" % definition)
        if self._is_service(name):
            service = self._services[name]
            reply = service['reply']
            if _is_stream(service):
                return Dump(name, reply, crc, filter(_is_request_field, fields), definition)
            if reply:
                return Request(name, reply, crc, filter(_is_request_field, fields), definition)
        elif self._is_reply(name):
            return Reply(name, self._requests_by_reply[name], crc, filter(_is_reply_field, fields), definition)
        elif self._is_details(name):
            return Details(name, self._dumps_by_details[name], crc, filter(_is_reply_field, fields), definition)

        raise ParseException("Unknown message type %s" % definition)
        # return Event(name, crc, filter(_is_reply_field, fields), definition)  #  todo

    def _is_service(self, name):
        return name in self._services

    def _is_reply(self, name):
        return name in self._requests_by_reply

    def _is_details(self, name):
        return name in self._dumps_by_details

    def _validate_messages(self):
        """
        In case if message A is known to be reply for message B, and message B was not correctly parsed,
        remove message A from the set of all messages
        """
        to_be_removed = []
        messages = self._messages_by_name
        for name, msg in messages.iteritems():
            if (is_request(msg) and msg.reply not in messages) \
                    or (is_reply(msg) and msg.request not in messages) \
                    or (is_dump(msg) and msg.details not in messages) \
                    or (is_details(msg) and msg.dump not in messages):
                to_be_removed.append(name)

        for name in to_be_removed:
            del messages[name]

        self.messages = self._messages_by_name.values()

