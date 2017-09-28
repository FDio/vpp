#!/usr/bin/env python2

import json


def msg_is_reply(name):
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


class Field(object):

    def __init__(
            self,
            field_name,
            field_type,
            array_len=None,
            nelem_field=None):
        self.name = field_name
        self.type = field_type
        self.len = array_len
        self.nelem_field = nelem_field

    def __str__(self):
        if self.len is None:
            return "name: %s, type: %s" % (self.name, self.type)
        elif self.len > 0:
            return "name: %s, type: %s, length: %s" % (self.name, self.type,
                                                       self.len)
        else:
            return ("name: %s, type: %s, variable length stored in: %s" %
                    (self.name, self.type, self.nelem_field))


class Type(object):
    def __init__(self, name):
        self.name = name


class SimpleType (Type):

    def __init__(self, name):
        super(SimpleType, self).__init__(name)

    def __str__(self):
        return self.name


def get_msg_header_defs(struct_type_class, field_class, typedict):
    return [
        struct_type_class(['msg_header1_t',
                           ['u16', '_vl_msg_id'],
                           ['u32', 'context'],
                           ],
                          typedict, field_class
                          ),
        struct_type_class(['msg_header2_t',
                           ['u16', '_vl_msg_id'],
                           ['u32', 'client_index'],
                           ['u32', 'context'],
                           ],
                          typedict, field_class
                          ),
    ]


class Struct(object):

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields
        self.field_names = [n.name for n in self.fields]


class Message(object):

    def __init__(self, logger, definition, typedict,
                 struct_type_class, simple_type_class, field_class):
        self.request = None
        self.logger = logger
        m = definition
        logger.debug("Parsing message definition `%s'" % m)
        name = m[0]
        self.name = name
        logger.debug("Message name is `%s'" % name)
        ignore = True
        self.header = None
        fields = []
        for header in get_msg_header_defs(struct_type_class, field_class,
                                          typedict):
            logger.debug("Probing header `%s'" % header.name)
            if header.is_part_of_def(m[1:]):
                self.header = header
                logger.debug("Found header `%s'" % header.name)
                fields.append(field_class(field_name='header',
                                          field_type=self.header))
                ignore = False
                break
        if ignore and not msg_is_reply(name):
            raise ParseError("While parsing message `%s': could not find all "
                             "common header fields" % name)
        for field in m[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                logger.debug("Found CRC `%s'" % self.crc)
                continue
            else:
                field_type = field[0]
                if field_type in typedict:
                    field_type = typedict[field_type]
                else:
                    field_type = typedict[remove_magic(field_type)]
                if len(field) == 2:
                    if self.header is not None and\
                            self.header.has_field(field[1]):
                        continue
                    p = field_class(field_name=field[1],
                                    field_type=field_type)
                elif len(field) == 3:
                    if field[2] == 0:
                        raise ParseError(
                            "While parsing message `%s': variable length "
                            "array `%s' doesn't have reference to member "
                            "containing the actual length" % (
                                name, field[1]))
                    p = field_class(
                        field_name=field[1],
                        field_type=field_type,
                        array_len=field[2])
                elif len(field) == 4:
                    nelem_field = None
                    for f in fields:
                        if f.name == field[3]:
                            nelem_field = f
                    if nelem_field is None:
                        raise ParseError(
                            "While parsing message `%s': couldn't find "
                            "variable length array `%s' member containing "
                            "the actual length `%s'" % (
                                name, field[1], field[3]))
                    p = field_class(
                        field_name=field[1],
                        field_type=field_type,
                        array_len=field[2],
                        nelem_field=nelem_field)
                else:
                    raise Exception("Don't know how to parse message "
                                    "definition for message `%s': `%s'" %
                                    (m, m[1:]))
                logger.debug("Parsed field `%s'" % p)
                fields.append(p)
        self.fields = fields

    def is_dump(self):
        return self.name.endswith('_dump')

    def is_reply(self):
        return msg_is_reply(self.name)


class StructType (Type, Struct):

    def __init__(self, definition, typedict, field_class):
        t = definition
        name = t[0]
        fields = []
        for field in t[1:]:
            if len(field) == 1 and 'crc' in field:
                self.crc = field['crc']
                continue
            elif len(field) == 2:
                p = field_class(field_name=field[1],
                                field_type=typedict[field[0]])
            elif len(field) == 3:
                if field[2] == 0:
                    raise ParseError("While parsing type `%s': array `%s' has "
                                     "variable length" % (name, field[1]))
                p = field_class(field_name=field[1],
                                field_type=typedict[field[0]],
                                array_len=field[2])
            else:
                raise ParseError(
                    "Don't know how to parse type definition for "
                    "type `%s': `%s'" % (t, t[1:]))
            fields.append(p)
        Type.__init__(self, name)
        Struct.__init__(self, name, fields)

    def has_field(self, name):
        return name in self.field_names

    def is_part_of_def(self, definition):
        for idx in range(len(self.fields)):
            field = definition[idx]
            p = self.fields[idx]
            if field[1] != p.name:
                return False
            if field[0] != p.type.name:
                raise ParseError(
                    "Unexpected field type `%s' (should be `%s'), "
                    "while parsing msg/def/field `%s/%s/%s'" %
                    (field[0], p.type, p.name, definition, field))
        return True


class JsonParser(object):
    def __init__(self, logger, files, simple_type_class=SimpleType,
                 struct_type_class=StructType, field_class=Field,
                 message_class=Message):
        self.messages = {}
        self.types = {
            x: simple_type_class(x) for x in [
                'i8', 'i16', 'i32', 'i64',
                'u8', 'u16', 'u32', 'u64',
                'f64'
            ]
        }

        self.simple_type_class = simple_type_class
        self.struct_type_class = struct_type_class
        self.field_class = field_class
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
                    type_ = self.struct_type_class(t, self.types,
                                                   self.field_class)
                    if type_.name in self.types:
                        raise ParseError("Duplicate type `%s'" % type_.name)
                except ParseError as e:
                    self.exceptions.append(e)
                    continue
                self.types[type_.name] = type_
                self.types_by_json[path][type_.name] = type_
            for m in j['messages']:
                try:
                    msg = self.message_class(self.logger, m, self.types,
                                             self.struct_type_class,
                                             self.simple_type_class,
                                             self.field_class)
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
            for e in self.exceptions:
                self.logger.error(e)
            raise Exception("No messages parsed.")
        for jn, j in self.messages_by_json.items():
            remove = []
            for n, m in j.items():
                try:
                    if not m.is_reply():
                        try:
                            m.reply = self.get_reply(n)
                            m.reply.request = m
                        except:
                            raise ParseError(
                                "Cannot find reply to message `%s'" % n)
                except ParseError as e:
                    self.exceptions.append(e)
                    remove.append(n)

            self.messages_by_json[jn] = {
                k: v for k, v in j.items() if k not in remove}
