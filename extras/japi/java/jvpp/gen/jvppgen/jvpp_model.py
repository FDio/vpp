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

import binascii

BASE_PACKAGE = "io.fd.vpp.jvpp"


class ParseException(Exception):
    pass


class Type(object):
    def __init__(self, name, java_name, java_name_fqn, jni_signature, jni_type, jni_accessor,
                 host_to_net_function, net_to_host_function):
        """
        Initializes Type class.

        :param name: name of type as defined in .api file, e.g. u8, u32[] or mac_entry
        :param java_name: corresponding java name, e.g. byte, int[] or MacEntry
        :param java_name_fqn: fully qualified java name, e.g. io.fd.vpp.jvpp.core.types.MacEntry
        :param jni_signature: JNI Type signature, e.g. B, [I or Lio.fd.vpp.jvpp.core.types.MacEntry;
                              See https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#type_signatures
        :param jni_type: JNI reference type, e.g. jbyte jintArray, jobject
                         See https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#reference_types
        :param jni_accessor: Java type do by used in Get<type>Field, Set<type>Field and other functions.
                             See https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#accessing_fields_of_objects
        :param host_to_net_function: name of function host to net byte order swap function
        :param net_to_host_function: name of function net to host byte order swap function
        """
        self.name = name
        self.java_name = java_name

        # Java generation specific properties, TODO(VPP-1186): move to Java specific subclass
        self.java_name_fqn = java_name_fqn

        # JNI generation specific properties, TODO(VPP-1186): move to JNI specific subclass
        self.jni_signature = jni_signature

        # Native type, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#primitive_types
        # and
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#reference_types
        self.jni_type = jni_type

        # Java type do by used in Get<type>Field, Set<type>Field and other functions, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#accessing_fields_of_objects
        self.jni_accessor = jni_accessor

        self.host_to_net_function = host_to_net_function
        self.net_to_host_function = net_to_host_function
        self.is_swap_needed = host_to_net_function and net_to_host_function


class SimpleType(Type):
    def __init__(self, name, java_name, jni_signature, jni_type, jni_accessor,
                 host_to_net_function=None, net_to_host_function=None):
        super(SimpleType, self).__init__(
            name=name,
            java_name=java_name,
            java_name_fqn=java_name,
            jni_signature=jni_signature,
            jni_type=jni_type,
            jni_accessor=jni_accessor,
            host_to_net_function=host_to_net_function,
            net_to_host_function=net_to_host_function
        )
        self.vpp_name = name

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return "%s = %s(%s)" % (net_ref_name, self.host_to_net_function, host_ref_name)

    def __str__(self):
        return "SimpleType{name:%s, java_name:%s}" % (self.name, self.java_name)


# TODO(VPP-1187): add array host to net functions to reduce number of members and simplify JNI generation
class Array(Type):
    def __init__(self, base_type, name=None):
        if name is None:
            name = base_type.name + _ARRAY_SUFFIX
        super(Array, self).__init__(
            name=name,
            java_name=base_type.java_name + _ARRAY_SUFFIX,
            java_name_fqn=base_type.java_name_fqn + _ARRAY_SUFFIX,
            jni_signature="[%s" % base_type.jni_signature,
            jni_type="%sArray" % base_type.jni_type,
            jni_accessor="Object",
            host_to_net_function=base_type.host_to_net_function,
            net_to_host_function=base_type.net_to_host_function
        )
        self.base_type = base_type

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return self.base_type.get_host_to_net_function(host_ref_name, net_ref_name)

    def __str__(self):
        return "Array{name:%s, java_name:%s}" % (self.name, self.java_name)


class Enum(Type):
    def __init__(self, name, value, constants, definition, plugin_name):
        _java_name = _underscore_to_camelcase_upper(name)

        super(Enum, self).__init__(
            name=name,
            java_name=_java_name,
            java_name_fqn="io.fd.vpp.jvpp.%s.types.%s" % (plugin_name, _java_name),
            jni_signature="Lio/fd/vpp/jvpp/%s/types/%s;" % (plugin_name, _java_name),
            jni_type="jobject",
            jni_accessor="Object",
            host_to_net_function="_host_to_net_%s" % name,
            net_to_host_function="_net_to_host_%s" % name
        )

        self.value = value
        self.constants = constants
        self.doc = _message_to_javadoc(definition)
        self.java_name_lower = _underscore_to_camelcase_lower(name)
        self.vpp_name = "%s%s%s" % (_VPP_TYPE_PREFIX, name, _VPP_TYPE_SUFFIX)
        # Fully qualified class name used by FindClass function, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#FindClass
        self.jni_name = "io/fd/vpp/jvpp/%s/types/%s" % (plugin_name, _java_name)

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return "_host_to_net_%s(env, %s, &(%s))" % (self.name, host_ref_name, net_ref_name)


class Class(Type):
    def __init__(self, name, crc, fields, definition, plugin_name):
        _java_name = _underscore_to_camelcase_upper(name)

        super(Class, self).__init__(
            name=name,
            java_name=_java_name,
            java_name_fqn="io.fd.vpp.jvpp.%s.types.%s" % (plugin_name, _java_name),
            jni_signature="Lio/fd/vpp/jvpp/%s/types/%s;" % (plugin_name, _java_name),
            jni_type="jobject",
            jni_accessor="Object",
            host_to_net_function="_host_to_net_%s" % name,
            net_to_host_function="_net_to_host_%s" % name
        )

        self.crc = crc
        self.fields = fields
        self.doc = _message_to_javadoc(definition)
        self.java_name_lower = _underscore_to_camelcase_lower(name)
        self.vpp_name = "%s%s%s" % (_VPP_TYPE_PREFIX, name, _VPP_TYPE_SUFFIX)
        # Fully qualified class name used by FindClass function, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#FindClass
        self.jni_name = "io/fd/vpp/jvpp/%s/types/%s" % (plugin_name, _java_name)

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return "_host_to_net_%s(env, %s, &(%s))" % (self.name, host_ref_name, net_ref_name)


class Union(Type):
    def __init__(self, name, crc, fields, definition, plugin_name):
        _java_name = _underscore_to_camelcase_upper(name)

        super(Union, self).__init__(
            name=name,
            java_name=_java_name,
            java_name_fqn="io.fd.vpp.jvpp.%s.types.%s" % (plugin_name, _java_name),
            jni_signature="Lio/fd/vpp/jvpp/%s/types/%s;" % (plugin_name, _java_name),
            jni_type="jobject",
            jni_accessor="Object",
            host_to_net_function="_host_to_net_%s" % name,
            net_to_host_function="_net_to_host_%s" % name
        )

        self.crc = crc
        self.fields = fields
        self.doc = _message_to_javadoc(definition)
        self.java_name_lower = _underscore_to_camelcase_lower(name)
        self.vpp_name = "%s%s%s" % (_VPP_TYPE_PREFIX, name, _VPP_TYPE_SUFFIX)
        # Fully qualified class name used by FindClass function, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#FindClass
        self.jni_name = "io/fd/vpp/jvpp/%s/types/%s" % (plugin_name, _java_name)

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return "_host_to_net_%s(env, %s, &(%s))" % (self.name, host_ref_name, net_ref_name)

class StatsT(Type):
    def __init__(self, name, crc, fields, definition, plugin_name):
        _java_name = _underscore_to_camelcase_upper(name)

        super(StatsT, self).__init__(
            name=name,
            java_name=_java_name,
            java_name_fqn="io.fd.vpp.jvpp.%s.types.%s" % (plugin_name, _java_name),
            jni_signature="Lio/fd/vpp/jvpp/%s/types/%s;" % (plugin_name, _java_name),
            jni_type="jobject",
            jni_accessor="Object",
            host_to_net_function="_host_to_net_%s" % name,
            net_to_host_function="_net_to_host_%s" % name
        )

        self.crc = crc
        self.fields = fields
        self.doc = _message_to_javadoc(definition)
        self.java_name_lower = _underscore_to_camelcase_lower(name)
        self.vpp_name = "%s%s%s" % (_VPP_TYPE_PREFIX, name, _VPP_TYPE_SUFFIX)
        # Fully qualified class name used by FindClass function, see:
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#FindClass
        self.jni_name = "io/fd/vpp/jvpp/%s/types/%s" % (plugin_name, _java_name)

    def get_host_to_net_function(self, host_ref_name, net_ref_name):
        return "_host_to_net_%s(env, %s, &(%s))" % (self.name, host_ref_name, net_ref_name)

class Field(object):
    def __init__(self, name, field_type, array_len=None, array_len_field=None):
        self.name = name
        self.java_name = _underscore_to_camelcase_lower(name)
        self.java_name_upper = _underscore_to_camelcase_upper(name)
        self.type = field_type
        self.array_len = array_len
        self.array_len_field = array_len_field

    def __str__(self):
        return "Field{name:%s, java_name:%s, type:%s}" % (self.name, self.java_name, self.type)


class Message(object):
    def __init__(self, name, crc, fields, definition):
        self.name = name
        self.java_name_upper = _underscore_to_camelcase_upper(name)
        self.java_name_lower = _underscore_to_camelcase_lower(name)
        self.crc = crc[2:]
        self.fields = fields
        self.has_fields = fields != []
        self.doc = _message_to_javadoc(definition)

    def __str__(self):
        return "Message{name:%s, java_name:%s, crc:%s, fields:%s}" % (
            self.name, self.java_name_upper, self.crc, self.fields)


class Event(Message):
    def __init__(self, name, crc, fields, definition):
        super(Event, self).__init__(name, crc, fields, definition)


class Request(Message):
    def __init__(self, name, reply, crc, fields, definition):
        super(Request, self).__init__(name, crc, fields, definition)
        self.reply = reply
        self.reply_java = _underscore_to_camelcase_upper(reply)

    def __str__(self):
        return "Request{name:%s, reply:%s, crc:%s, fields:%s}" % (self.name, self.reply, self.crc, self.fields)


class Reply(Message):
    def __init__(self, name, request, crc, fields, definition):
        super(Reply, self).__init__(name, crc, fields, definition)
        self.request = request
        self.request_java = _underscore_to_camelcase_upper(request)

    def __str__(self):
        return "Reply{name:%s, request:%s, crc:%s, fields:%s}" % (self.name, self.request, self.crc, self.fields)


class Dump(Message):
    def __init__(self, name, details, crc, fields, definition):
        super(Dump, self).__init__(name, crc, fields, definition)
        self.details = details
        self.reply_java = _underscore_to_camelcase_upper(details)

    def __str__(self):
        return "Dump{name:%s, details:%s, crc:%s, fields:%s}" % (self.name, self.details, self.crc, self.fields)


class Details(Message):
    def __init__(self, name, dump, crc, fields, definition):
        super(Details, self).__init__(name, crc, fields, definition)
        self.dump = dump
        self.request_java = _underscore_to_camelcase_upper(dump)

    def __str__(self):
        return "Details{name:%s, dump:%s, crc:%s, fields:%s}" % (self.name, self.dump, self.crc, self.fields)


def is_retval(field):
    return field.name == u'retval'


def is_array(field):
    return field.array_len is not None


def is_request(msg):
    return hasattr(msg, 'reply')


def is_reply(msg):
    return hasattr(msg, 'request')


def is_dump(msg):
    return hasattr(msg, 'details')


def is_details(msg):
    return hasattr(msg, 'dump')


def is_event(msg):
    return isinstance(msg, Event)


def is_control_ping(msg):
    return msg.name == u'control_ping'


def is_control_ping_reply(msg):
    return msg.name == u'control_ping_reply'


def crc(block):
    s = str(block).encode()
    return binascii.crc32(s) & 0xffffffff


class JVppModel(object):
    def __init__(self, logger, json_api_files, plugin_name):
        self.logger = logger
        # TODO(VPP-1188): provide json_file_by_definition map to improve javadoc
        self.json_api_files = json_api_files
        self.plugin_package = BASE_PACKAGE + "." + plugin_name
        self.plugin_name = plugin_name
        self.plugin_java_name = _underscore_to_camelcase_upper(plugin_name)
        self._load_json_files(json_api_files)
        self._parse_services()
        self._parse_messages()
        self._validate_messages()

    def _load_json_files(self, json_api_files):
        types = {}
        self._messages = []
        self._services = {}
        self._aliases = {}
        for file_name in json_api_files:
            with open(file_name) as f:
                j = json.load(f)
                types.update({d[0]: {'type': 'enum', 'data': d} for d in j['enums']})
                types.update({d[0]: {'type': 'type', 'data': d} for d in j['types']})
                types.update({d[0]: {'type': 'union', 'data': d} for d in j['unions']})
                self._messages.extend(j['messages'])
                self._services.update(j['services'])
                self._aliases.update(j['aliases'])

        self._parse_types(types)

    def _parse_aliases(self, types):

        # model aliases
        for alias_name in self._aliases:
            alias = self._aliases[alias_name]
            alias_type = {"type": "type"}
            java_name_lower = _underscore_to_camelcase_lower(alias_name)
            vpp_type = alias["type"]
            crc_value = '0x%08x' % crc(alias_name)
            if "length" in alias:
                length = alias["length"]
                alias_type["data"] = [
                    alias_name,
                    [
                        vpp_type,
                        java_name_lower,
                        length
                    ],
                    {
                        "crc": crc_value
                    }
                ]
            else:
                alias_type["data"] = [
                    alias_name,
                    [
                        vpp_type,
                        java_name_lower
                    ],
                    {
                        "crc": crc_value
                    }
                ]

            types[alias_name] = alias_type

    def _parse_types(self, types):
        self._parse_simple_types()
        self._parse_aliases(types)
        i = 0
        while True:
            unresolved = {}
            for name, value in types.items():
                if name in self._types_by_name:
                    continue

                type = value['type']
                data = value['data'][1:]
                try:
                    if type == 'enum':
                        type = self._parse_enum(name, data)
                    elif type == 'union':
                        type = self._parse_union(name, data)
                    elif type == 'type':
                        type = self._parse_type(name, data)
                    #elif type == 'stats_t':
                     #   type = self._parse_stats_t(name, data)
                    else:
                        self.logger.warning("Unsupported type %s. Ignoring...", type)
                        continue

                    self._types_by_name[name] = type
                    self._types_by_name[name + _ARRAY_SUFFIX] = Array(type)
                except ParseException as e:
                    self.logger.debug("Failed to parse %s type in iteration %s: %s.", name, i, e)
                    unresolved[name] = value
            if len(unresolved) == 0:
                break
            if i > 3:
                raise ParseException('Unresolved type definitions {}'
                                     .format(unresolved))
            types = unresolved
            i += 1

        self.types = self._types_by_name.values()

    def _parse_simple_types(self):
        # Mapping according to:
        # http://docs.oracle.com/javase/7/do+'[]'cs/technotes/guides/jni/spec/types.html
        # and
        # https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#Get_type_Field_routines
        #
        # Unsigned types are converted to signed java types that have the same size.
        # It is the API user responsibility to interpret them correctly.

        self._types_by_name = OrderedDict({
            'u8': SimpleType('u8', 'byte', 'B', 'jbyte', 'Byte'),
            'i8': SimpleType('i8', 'byte', 'B', 'jbyte', 'Byte'),
            'u16': SimpleType('u16', 'short', 'S', 'jshort', 'Short',
                              host_to_net_function='clib_host_to_net_u16',
                              net_to_host_function='clib_net_to_host_u16'),
            'i16': SimpleType('i16', 'short', 'S', 'jshort', 'Short',
                              host_to_net_function='clib_host_to_net_i16',
                              net_to_host_function='clib_net_to_host_i16'),
            'u32': SimpleType('u32', 'int', 'I', 'jint', 'Int',
                              host_to_net_function='clib_host_to_net_u32',
                              net_to_host_function='clib_net_to_host_u32'),
            'i32': SimpleType('i32', 'int', 'I', 'jint', 'Int',
                              host_to_net_function='clib_host_to_net_i32',
                              net_to_host_function='clib_net_to_host_i32'),
            'u64': SimpleType('u64', 'long', 'J', 'jlong', 'Long',
                              host_to_net_function='clib_host_to_net_u64',
                              net_to_host_function='clib_net_to_host_u64'),
            'i64': SimpleType('i64', 'long', 'J', 'jlong', 'Long',
                              host_to_net_function='clib_host_to_net_i64',
                              net_to_host_function='clib_net_to_host_i64'),
            'f64': SimpleType('f64', 'double', 'D', 'jdouble', 'Double'),
            'string': SimpleType('string', 'String', 'l', 'jstring', 'Object',
                                 host_to_net_function='_host_to_net_string',
                                 net_to_host_function='_net_to_host_string',)
        })

        for n, t in self._types_by_name.items():
            self._types_by_name[n + _ARRAY_SUFFIX] = Array(t)

    def _parse_enum(self, name, definition):
        self.logger.debug("Parsing enum %s: %s", name, definition)
        constants = []
        type_name = None
        for item in definition:
            if type(item) is dict and 'enumtype' in item:
                type_name = item['enumtype']
                continue
            constants.append({'name': item[0], 'value': item[1]})
        if not type_name:
            raise ParseException("'enumtype' was not defined for %s" % definition)
        return Enum(name, Field('value', self._types_by_name[type_name]), constants, definition, self.plugin_name)

    def _parse_union(self, name, definition):
        self.logger.debug("Parsing union %s: %s", name, definition)
        crc, fields = self._parse_fields(definition)
        return Union(name, crc, fields, definition, self.plugin_name)

    def _parse_stats_t(self, name, definition):
        self.logger.debug("Parsing stats_t %s: %s", name, definition)
        crc, fields = self._parse_fields(definition)
        return StatsT(name, crc, fields, definition, self.plugin_name)

    def _parse_type(self, name, definition):
        self.logger.debug("Parsing type %s: %s", name, definition)
        crc, fields = self._parse_fields(definition)
        return Class(name, crc, fields, definition, self.plugin_name)

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
        for msg in self._messages:
            try:
                name = msg[0]
                definition = msg[1:]
                self._messages_by_name[name] = self._parse_message(name, definition)
            except ParseException as e:
                self.logger.warning("Failed to parse message %s: %s. Skipping message.", name, e)

    def _parse_message(self, name, definition):
        self.logger.debug("Parsing message %s: %s", name, definition)
        crc, fields = self._parse_fields(definition)
        if name in self._services:
            service = self._services[name]
            reply = service['reply']
            if _is_stream(service):
                return Dump(name, reply, crc, filter(_is_request_field, fields), definition)
            if reply:
                return Request(name, reply, crc, filter(_is_request_field, fields), definition)
            else:
                return Event(name, crc, filter(_is_request_field, fields), definition)
        elif name in self._requests_by_reply:
            return Reply(name, self._requests_by_reply[name], crc, filter(_is_reply_field, fields), definition)
        elif name in self._dumps_by_details:
            return Details(name, self._dumps_by_details[name], crc, filter(_is_reply_field, fields), definition)
        else:
            # TODO: some messages like combined_counters are not visible in the services.
            # Throw exception instead (requires fixing vppagigen).
            return Event(name, crc, filter(_is_request_field, fields), definition)

    def _parse_fields(self, definition):
        crc = None
        fields = []
        for item in definition:
            if type(item) == dict and 'crc' in item:
                crc = item['crc']
            else:
                fields.append(self._parse_field(item, fields))
        if not crc:
            raise ParseException("CRC was not defined for %s" % definition)
        return crc, fields

    def _parse_field(self, field, fields):
        type_name = _extract_type_name(field[0])

        if type_name in self._types_by_name:
            if len(field) > 2:
                # Array field
                array_len_field = None
                if len(field) == 4:
                    for f in fields:
                        if f.name == field[3]:
                            array_len_field = f
                    if not array_len_field:
                        raise ParseException("Could not find field %s declared as length of array %s",
                                             field[3], field[1])
                return Field(field[1], self._types_by_name[type_name + _ARRAY_SUFFIX], field[2], array_len_field)
            else:
                return Field(field[1], self._types_by_name[type_name])
        else:
            raise ParseException("Unknown field type %s" % field)

    def _validate_messages(self):
        """
        In case if message A is known to be reply for message B, and message B was not correctly parsed,
        remove message A from the set of all messages.
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


_ARRAY_SUFFIX = '[]'


def _underscore_to_camelcase_upper(name):
    return name.title().replace("_", "")


def _underscore_to_camelcase_lower(name):
    name = name.title().replace("_", "")
    return name[0].lower() + name[1:]


def _message_to_javadoc(message_definition):
    """ Converts JSON message definition to javadoc """
    formatted_message = pprint.pformat(message_definition, indent=4, width=120, depth=None)
    return " * " + formatted_message.replace("\n", "\n * ")


def _is_stream(service):
    """
    Checks if service represents stream, e.g.:
    "ip_address_dump": {
        "reply": "ip_address_details",
        "stream": true
    }
    :param service: JSON definition of service
    :return: value assigned to "stream" or None
    """
    return "stream" in service


def _extract_type_name(name):
    if name.startswith(_VPP_TYPE_PREFIX) and name.endswith(_VPP_TYPE_SUFFIX):
        return name[len(_VPP_TYPE_PREFIX): - len(_VPP_TYPE_SUFFIX)]
    return name

_VPP_TYPE_PREFIX = "vl_api_"

_VPP_TYPE_SUFFIX = "_t"


def _is_request_field(field):
    # Skip fields that are hidden to the jvpp user (handled by JNI layer)
    return field.name not in {'_vl_msg_id', 'client_index', 'context'}


def _is_reply_field(field):
    # Skip fields that are hidden to the jvpp user:
    # _vl_msg_id is handled at JNI layer,
    # Unlike in the request case, context is visible to allow matching replies with requests at Java layer.
    return field.name not in {'_vl_msg_id'}
