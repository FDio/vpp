#!/usr/bin/env python3

import json
from abc import ABCMeta


def msg_is_reply_only(name):
    return name.endswith('_reply') or name.endswith('_details') \
        or name.endswith('_event') or name.endswith('_counters')


class ParseError (Exception):
    pass


magic_prefix = "vl_api_"
magic_suffix = "_t"


def remove_magic(what):
    if what.startswith(magic_prefix) and what.endswith(magic_suffix):
        return what[len(magic_prefix): - len(magic_suffix)]
    return what


class Parameter:

    def __init__(
            self,
            param_name,
            param_type,
            array_len=None,
            nelem_param=None):
        self.name = param_name
        self.type = param_type
        self.len = array_len
        self.nelem_param = nelem_param


class MsgHeaderDef(object):
    def __init__(self, name, fields, param_class=Parameter):
        self.name = name
        self.param_class = param_class
        self.fields = fields
        self.field_names = [n.name for n in self.fields]

    def has_field(self, name):
        return name in self.field_names

    def is_part_of_def(self, definition):
        for idx in range(len(self.fields)):
            field = definition[idx]
            p = self.fields[idx]
            if field[1] != p.name:
                return False
            if field[0] != p.type:
                raise ParseError(
                    "Unexpected field type `%s' (should be `%s'), "
                    "while parsing msg/def/field `%s/%s/%s'" %
                    (field[0], p.type, p.name, definition, field))
        return True


def get_msg_header_defs(param_class=Parameter):
    return [
        MsgHeaderDef(
            name='vapi_msg_header1_t',
            fields=[param_class(param_type='u16', param_name='_vl_msg_id'),
                    param_class(param_type='u32', param_name='context')
                    ]
        ),
        MsgHeaderDef(
            name='vapi_msg_header2_t',
            fields=[param_class(param_type='u16', param_name='_vl_msg_id'),
                    param_class(param_type='u32', param_name='client_index'),
                    param_class(param_type='u32', param_name='context')
                    ]
        ),
    ]


class Struct:

    def __init__(self, name, parameters):
        self.name = name
        self.parameters = parameters


class Message:

    def __init__(self, definition, typedict, swap_to_be_dict,
                 swap_to_host_dict, param_class=Parameter):
        self.swap_to_be_dict = swap_to_be_dict
        self.swap_to_host_dict = swap_to_host_dict
        m = definition
        name = m[0]
        ignore = True
        self.header = None
        for header in get_msg_header_defs(param_class):
            if header.is_part_of_def(m[1:]):
                self.header = header
                ignore = False
                break
        if ignore and not msg_is_reply_only(name):
            raise ParseError("while parsing message `%s': could not find all "
                             "common header fields" % name)
        parameters = []
        for field in m[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                continue
            else:
                param_type = field[0]
                if param_type in typedict:
                    param_type = typedict[param_type]
                else:
                    param_type = typedict[remove_magic(param_type)]
                if len(field) == 2:
                    p = param_class(param_name=field[1],
                                    param_type=param_type)
                elif len(field) == 3:
                    if field[2] == 0:
                        raise ParseError(
                            "while parsing message `%s': variable length "
                            "array `%s' doesn't have reference to member "
                            "containing the actual length" % (
                                name, field[1]))
                    p = param_class(
                        param_name=field[1],
                        param_type=param_type,
                        array_len=field[2])
                elif len(field) == 4:
                    p = param_class(
                        param_name=field[1],
                        param_type=param_type,
                        array_len=field[2],
                        nelem_param=field[3])
                else:
                    raise Exception("Don't know how to parse message "
                                    "definition for message `%s': `%s'" %
                                    (m, m[1:]))
                parameters.append(p)
        self.name = name
        self.parameters = parameters

    def is_dump(self):
        return self.name.endswith('_dump')

    def is_reply_only(self):
        return msg_is_reply_only(self.name)


class Type:
    __metaclass__ = ABCMeta

    def __init__(self, name):
        self.name = name


class SimpleType (Type):

    def __init__(self, name):
        super().__init__(name)


class StructType (Type, Struct):

    def __init__(self, definition, typedict, param_class=Parameter):
        t = definition
        name = t[0]
        parameters = []
        for field in t[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                continue
            elif len(field) == 2:
                p = param_class(param_name=field[1],
                                param_type=typedict[field[0]])
            elif len(field) == 3:
                if field[2] == 0:
                    raise ParseError("while parsing type `%s': array `%s' has "
                                     "variable length" % (name, field[1]))
                p = param_class(param_name=field[1],
                                param_type=typedict[field[0]],
                                array_len=field[2])
            else:
                raise ParseError(
                    "Don't know how to parse type definition for "
                    "type `%s': `%s'" % (t, t[1:]))
            parameters.append(p)
        Type.__init__(self, name)
        Struct.__init__(self, name, parameters)


class JsonParser:
    swap_to_be_dict = {
        'i16': 'htobe16', 'u16': 'htobe16',
        'i32': 'htobe32', 'u32': 'htobe32',
        'i64': 'htobe64', 'u64': 'htobe64',
    }

    swap_to_host_dict = {
        'i16': 'be16toh', 'u16': 'be16toh',
        'i32': 'be32toh', 'u32': 'be32toh',
        'i64': 'be64toh', 'u64': 'be64toh',
    }

    def __init__(self, logger, files, simple_type_class=SimpleType,
                 struct_type_class=StructType, message_class=Message):
        self.messages = {}
        self.types = {
            x: simple_type_class(x) for x in [
                'i8', 'i16', 'i32', 'i64',
                'u8', 'u16', 'u32', 'u64',
                'f64'
            ]
        }
        self.struct_type_class = struct_type_class
        self.message_class = message_class

        self.exceptions = []
        self.json_files = []
        self.types_by_json = {}
        self.messages_by_json = {}
        self.logger = logger
        for f in files:
            self.parse_json_file(f)
        self.finalize_parsing()

    def parse_json_file(self, path):
        self.logger.info("Parsing json api file: `%s'" % path)
        self.json_files.append(path)
        self.types_by_json[path] = {}
        self.messages_by_json[path] = {}
        with open(path) as f:
            j = json.load(f)
            for t in j['types']:
                try:
                    type_ = self.struct_type_class(t, self.types)
                    if type_.name in self.types:
                        raise ParseError("Duplicate type `%s'" % type_.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.types[type_.name] = type_
                self.types_by_json[path][type_.name] = type_
            for m in j['messages']:
                try:
                    msg = self.message_class(m, self.types,
                                             self.swap_to_be_dict,
                                             self.swap_to_host_dict)
                    if msg.name in self.messages:
                        raise ParseError("Duplicate message `%s'" % msg.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.messages[msg.name] = msg
                self.messages_by_json[path][msg.name] = msg

    def get_reply(self, message):
        if self.messages[message].is_dump():
            return self.messages["%s_details" % message[:-len("_dump")]]
        return self.messages["%s_reply" % message]

    def finalize_parsing(self):
        if len(self.messages) == 0:
            raise Exception("No messages parsed.")
        for jn, j in self.messages_by_json.items():
            remove = []
            for n, m in j.items():
                try:
                    if not m.is_reply_only():
                        try:
                            m.reply = self.get_reply(n)
                        except:
                            raise ParseError(
                                "cannot find reply to message `%s'" % n)
                except ParseError as e:
                    self.exceptions.append(e)
                    remove.append(n)

            self.messages_by_json[jn] = {
                k: v for k, v in j.items() if k not in remove}
