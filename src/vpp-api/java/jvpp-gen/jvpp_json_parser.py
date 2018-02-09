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


def underscore_to_camelcase_upper(name):
    return name.title().replace("_", "")


def underscore_to_camelcase_lower(name):
    name = name.title().replace("_", "")
    return name[0].lower() + name[1:]


class Type(object):
    def __init__(self, name):
        self.name = name


class SimpleType(Type):
    def __init__(self, name, java_name, jni_signature, jni_type, jni_accessor, host_to_net_function="",
                 net_to_host_function=""):
        super(SimpleType, self).__init__(name)
        self.java_name = java_name
        self.jni_signature = jni_signature
        self.jni_type = jni_type
        self.jni_accessor = jni_accessor
        self.host_to_net_function = host_to_net_function
        self.net_to_host_function = net_to_host_function

    def __str__(self):
        return "SimpleType{name:%s, java_name:%s}" % (self.name, self.java_name)


class Class(Type):
    def __init__(self, name, crc, fields):
        super(Class, self).__init__(name)
        self.crc = crc
        self.fields = fields


class Array(Type):
    def __init__(self, name, length, length_field):
        super(Array, self).__init__(name)
        self.length = length
        self.length_field = length_field


class Field(object):
    def __init__(self, name, field_type):
        self.name = name
        self.java_name = underscore_to_camelcase_lower(name)
        self.type = field_type

    def __str__(self):
        return "Field{name:%s, java_name:%s, type:%s}" % (self.name, self.java_name, self.type)


def _message_to_javadoc(message_definition):
    """ Converts JSON message definition to javadoc """
    formatted_message = pprint.pformat(message_definition, indent=4, width=120, depth=None)
    return " * " + formatted_message.replace("\n", "\n * ")


# fixme use optional parameters instead of subclasses,
# it will translate to potentailly faster code, e.g.
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


def is_request(msg):
    return hasattr(msg, 'reply')


def is_reply(msg):
    return hasattr(msg, 'request')


def is_dump(msg):
    return hasattr(msg, 'details')


class Event(Message):
    def __init__(self, name, crc, fields, definition):
        super(Event, self).__init__(name, crc, fields, definition)


class Request(Message):
    def __init__(self, name, reply, crc, fields, definition):
        super(Request, self).__init__(name, crc, fields, definition)
        self.reply = underscore_to_camelcase_upper(reply)

    def __str__(self):
        return "Request{name:%s, reply:%s, crc:%s, fields:%s}" % (self.name, self.reply, self.crc, self.fields)


class Reply(Message):
    def __init__(self, name, request, crc, fields, definition):
        super(Reply, self).__init__(name, crc, fields, definition)
        self.request = underscore_to_camelcase_upper(request)

    def __str__(self):
        return "Reply{name:%s, request:%s, crc:%s, fields:%s}" % (self.name, self.request, self.crc, self.fields)


class Dump(Message):
    def __init__(self, name, details, crc, fields, definition):
        super(Dump, self).__init__(name, crc, fields, definition)
        self.details = underscore_to_camelcase_upper(details)

    def __str__(self):
        return "Dump{name:%s, details:%s, crc:%s, fields:%s}" % (self.name, self.details, self.crc, self.fields)


class Details(Message):
    def __init__(self, name, dump, crc, fields, definition):
        super(Details, self).__init__(name, crc, fields, definition)
        self.dump = underscore_to_camelcase_upper(dump)

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


# todo rename to json API
class JsonParser(object):
    def __init__(self, logger, json_api_files, plugin_name):
        self.logger = logger
        self.json_api_files = json_api_files  # todo provide json_file_by_definition map to improve javadoc
        self.plugin_package = BASE_PACKAGE + "." + plugin_name
        self.plugin_name = plugin_name
        self.plugin_java_name = underscore_to_camelcase_upper(plugin_name)
        logger.info("Hello")  # todo better logs
        logger.info(json_api_files)

        self._load_json_files(json_api_files)
        self._parse_types()
        self._parse_services()
        self._parse_messages()

    def _load_json_files(self, json_api_files):
        self._enums = []
        self._types = []
        _messages = []
        self._services = {}
        for file_name in json_api_files:
            with open(file_name) as f:
                j = json.load(f)
                self._enums.extend(j['enums'])
                self._types.extend(j['types'])
                _messages.extend(j['messages'])
                self._services.update(j['services'])

        self.json_messages_by_name = dict([(m[0], m[1:]) for m in _messages])

    def _parse_types(self):
        # Mapping according to:
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
        # and
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#Get_type_Field_routines
        #
        # Unsigned types are converted to signed java types that have the same size.
        # It is the API user responsibility to interpret them correctly.

        self.types = {
            'u8': SimpleType('u8', 'byte', 'B', 'jbyte', 'ByteField'),
            'i8': SimpleType('i8', 'byte', 'B', 'jbyte', 'ByteField'),
            'u16': SimpleType('u16', 'short', 'S', 'jshort', 'ShortField',
                              host_to_net_function= 'clib_host_to_net_u16',
                              net_to_host_function='clib_net_to_host_u16'),
            'i16': SimpleType('i16', 'short', 'S', 'jshort', 'ShortField',
                              host_to_net_function= 'clib_host_to_net_i16',
                              net_to_host_function='clib_net_to_host_i16'),
            'u32': SimpleType('u32', 'int', 'I', 'jint', 'IntField',
                              host_to_net_function= 'clib_host_to_net_u32',
                              net_to_host_function='clib_net_to_host_u32'),
            'i32': SimpleType('i32', 'int', 'I', 'jint', 'IntField',
                              host_to_net_function= 'clib_host_to_net_i32',
                              net_to_host_function='clib_net_to_host_i32'),
            'u64': SimpleType('u64', 'long', 'J', 'jlong', 'LongField',
                              host_to_net_function= 'clib_host_to_net_u64',
                              net_to_host_function='clib_net_to_host_u64'),
            'i64': SimpleType('i64', 'long', 'J', 'jlong', 'LongField',
                              host_to_net_function= 'clib_host_to_net_i64',
                              net_to_host_function='clib_net_to_host_i64'),
            'f64': SimpleType('f64', 'double', 'D', 'jdouble', 'DoubleField')
        }

    def _parse_services(self):
        self._dumps_by_details = {}
        self._requests_by_reply = {}
        for name, service in self._services.iteritems():
            if _is_stream(service):
                self._dumps_by_details[service['reply']] = name
            else:
                self._requests_by_reply[service['reply']] = name

    def _parse_messages(self):
        self.messages = []
        for name, definition in self.json_messages_by_name.iteritems():
            self.messages.append(self._parse_message(name, definition))

    def _parse_message(self, name, definition):
        crc = None
        fields = []
        for item in definition:
            if _is_crc(item):
                crc = item['crc']
            elif item[0] in self.types:
                fields.append(Field(item[1], self.types[item[0]]))
            else:
                raise Exception("Don't know how to parse %s defined in message %s." % (item, name))
        # todo validation (fail if crc is missing, etc/)
        if self.is_service(name):
            service = self._services[name]
            if _is_stream(service):
                return Dump(name, service['reply'], crc, filter(_is_request_field, fields), definition)
            return Request(name, service['reply'], crc, filter(_is_request_field, fields), definition)
        elif self.is_reply(name):
            return Reply(name, self._requests_by_reply[name], crc, filter(_is_reply_field, fields), definition)
        elif self.is_details(name):
            return Details(name, self._dumps_by_details[name], crc, filter(_is_reply_field, fields), definition)
        return Event(name, crc, [])

    def is_service(self, name):
        return name in self._services

    def is_reply(self, name):
        return name in self._requests_by_reply

    def is_details(self, name):
        return name in self._dumps_by_details
