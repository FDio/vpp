#!/usr/bin/env python3

import json


class ParseError(Exception):
    pass


magic_prefix = "vl_api_"
magic_suffix = "_t"


def remove_magic(what):
    if what.startswith(magic_prefix) and what.endswith(magic_suffix):
        return what[len(magic_prefix) : -len(magic_suffix)]
    return what


class Field(object):
    def __init__(self, field_name, field_type, array_len=None, nelem_field=None):
        self.name = field_name
        self.type = field_type
        self.len = array_len
        self.nelem_field = nelem_field

    def __str__(self):
        if self.len is None:
            return "Field(name: %s, type: %s)" % (self.name, self.type)
        elif type(self.len) == dict:
            return "Field(name: %s, type: %s, length: %s)" % (
                self.name,
                self.type,
                self.len,
            )
        elif self.len > 0:
            return "Field(name: %s, type: %s, length: %s)" % (
                self.name,
                self.type,
                self.len,
            )
        else:
            return "Field(name: %s, type: %s, variable length stored in: %s)" % (
                self.name,
                self.type,
                self.nelem_field,
            )

    def is_vla(self):
        return self.nelem_field is not None

    def has_vla(self):
        return self.is_vla() or self.type.has_vla()


class Alias(Field):
    pass


class Type(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class SimpleType(Type):
    def has_vla(self):
        return False


def get_msg_header_defs(struct_type_class, field_class, json_parser, logger):
    return [
        struct_type_class(
            [
                "msg_header1_t",
                ["u16", "_vl_msg_id"],
                ["u32", "context"],
            ],
            json_parser,
            field_class,
            logger,
        ),
        struct_type_class(
            [
                "msg_header2_t",
                ["u16", "_vl_msg_id"],
                ["u32", "client_index"],
                ["u32", "context"],
            ],
            json_parser,
            field_class,
            logger,
        ),
    ]


class Struct(object):
    def __init__(self, name, fields):
        self.name = name
        self.fields = fields
        self.field_names = [n.name for n in self.fields]
        self.depends = [f.type for f in self.fields]

    def __str__(self):
        return "[%s]" % "], [".join([str(f) for f in self.fields])

    def has_vla(self):
        for f in self.fields:
            if f.has_vla():
                return True
        return False


class Enum(SimpleType):
    def __init__(self, name, value_pairs, enumtype):
        super(Enum, self).__init__(name)
        self.type = enumtype
        self.value_pairs = value_pairs

    def __str__(self):
        return "Enum(%s, [%s])" % (
            self.name,
            "], [".join(["%s => %s" % (i, j) for i, j in self.value_pairs]),
        )


class Union(Type):
    def __init__(self, name, type_pairs, crc):
        Type.__init__(self, name)
        self.crc = crc
        self.type_pairs = type_pairs
        self.depends = [t for t, _ in self.type_pairs]

    def __str__(self):
        return "Union(%s, [%s])" % (
            self.name,
            "], [".join(["%s %s" % (i, j) for i, j in self.type_pairs]),
        )

    def has_vla(self):
        return False


class Message(object):
    def __init__(self, logger, definition, json_parser):
        struct_type_class = json_parser.struct_type_class
        field_class = json_parser.field_class
        self.request = None
        self.logger = logger
        m = definition
        logger.debug("Parsing message definition `%s'" % m)
        name = m[0]
        self.name = name
        logger.debug("Message name is `%s'" % name)
        ignore = True
        self.header = None
        self.is_reply = json_parser.is_reply(self.name)
        self.is_event = json_parser.is_event(self.name)
        self.is_stream = json_parser.is_stream(self.name)
        fields = []
        for header in get_msg_header_defs(
            struct_type_class, field_class, json_parser, logger
        ):
            logger.debug("Probing header `%s'" % header.name)
            if header.is_part_of_def(m[1:]):
                self.header = header
                logger.debug("Found header `%s'" % header.name)
                fields.append(field_class(field_name="header", field_type=self.header))
                ignore = False
                break
        if ignore and not self.is_event and not self.is_reply:
            raise ParseError(
                "While parsing message `%s': could not find all "
                "common header fields" % name
            )
        for field in m[1:]:
            if isinstance(field, dict) and "crc" in field:
                self.crc = field["crc"]
                logger.debug("Found CRC `%s'" % self.crc)
                continue
            else:
                field_type = json_parser.lookup_type_like_id(field[0])
                logger.debug("Parsing message field `%s'" % field)
                l = len(field)
                if any(type(n) is dict for n in field):
                    l -= 1
                if l == 2:
                    if self.header is not None and self.header.has_field(field[1]):
                        continue
                    p = field_class(field_name=field[1], field_type=field_type)
                elif l == 3:
                    if field[2] == 0 and field[0] != "string":
                        raise ParseError(
                            "While parsing message `%s': variable length "
                            "array `%s' doesn't have reference to member "
                            "containing the actual length" % (name, field[1])
                        )
                    if field[0] == "string" and field[2] > 0:
                        field_type = json_parser.lookup_type_like_id("u8")

                    p = field_class(
                        field_name=field[1], field_type=field_type, array_len=field[2]
                    )
                elif l == 4:
                    nelem_field = None
                    for f in fields:
                        if f.name == field[3]:
                            nelem_field = f
                    if nelem_field is None:
                        raise ParseError(
                            "While parsing message `%s': couldn't find "
                            "variable length array `%s' member containing "
                            "the actual length `%s'" % (name, field[1], field[3])
                        )
                    p = field_class(
                        field_name=field[1],
                        field_type=field_type,
                        array_len=field[2],
                        nelem_field=nelem_field,
                    )
                else:
                    raise Exception(
                        "Don't know how to parse message "
                        "definition for message `%s': `%s'" % (m, m[1:])
                    )
                logger.debug("Parsed field `%s'" % p)
                fields.append(p)
        self.fields = fields
        self.depends = [f.type for f in self.fields]
        logger.debug("Parsed message: %s" % self)

    def __str__(self):
        return "Message(%s, [%s], {crc: %s}" % (
            self.name,
            "], [".join([str(f) for f in self.fields]),
            self.crc,
        )


class StructType(Type, Struct):
    def __init__(self, definition, json_parser, field_class, logger):
        t = definition
        logger.debug("Parsing struct definition `%s'" % t)
        name = t[0]
        fields = []
        for field in t[1:]:
            if len(field) == 1 and "crc" in field:
                self.crc = field["crc"]
                continue
            field_type = json_parser.lookup_type_like_id(field[0])
            logger.debug("Parsing type field `%s'" % field)
            if len(field) == 2:
                p = field_class(field_name=field[1], field_type=field_type)
            elif len(field) == 3:
                if field[2] == 0:
                    raise ParseError(
                        "While parsing type `%s': array `%s' has "
                        "variable length" % (name, field[1])
                    )
                p = field_class(
                    field_name=field[1], field_type=field_type, array_len=field[2]
                )
            elif len(field) == 4:
                nelem_field = None
                for f in fields:
                    if f.name == field[3]:
                        nelem_field = f
                if nelem_field is None:
                    raise ParseError(
                        "While parsing message `%s': couldn't find "
                        "variable length array `%s' member containing "
                        "the actual length `%s'" % (name, field[1], field[3])
                    )
                p = field_class(
                    field_name=field[1],
                    field_type=field_type,
                    array_len=field[2],
                    nelem_field=nelem_field,
                )
            else:
                raise ParseError(
                    "Don't know how to parse field `%s' of type definition "
                    "for type `%s'" % (field, t)
                )
            fields.append(p)
        Type.__init__(self, name)
        Struct.__init__(self, name, fields)

    def __str__(self):
        return "StructType(%s, %s)" % (Type.__str__(self), Struct.__str__(self))

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
                    "while parsing msg/def/field `%s/%s/%s'"
                    % (field[0], p.type, p.name, definition, field)
                )
        return True


class JsonParser(object):
    def __init__(
        self,
        logger,
        files,
        simple_type_class=SimpleType,
        enum_class=Enum,
        union_class=Union,
        struct_type_class=StructType,
        field_class=Field,
        message_class=Message,
        alias_class=Alias,
    ):
        self.services = {}
        self.messages = {}
        self.enums = {}
        self.enumflags = {}
        self.unions = {}
        self.aliases = {}
        self.types = {
            x: simple_type_class(x)
            for x in [
                "i8",
                "i16",
                "i32",
                "i64",
                "u8",
                "u16",
                "u32",
                "u64",
                "f64",
                "bool",
            ]
        }

        self.types["string"] = simple_type_class("vl_api_string_t")
        self.replies = set()
        self.events = set()
        self.streams = set()
        self.simple_type_class = simple_type_class
        self.enum_class = enum_class
        self.union_class = union_class
        self.struct_type_class = struct_type_class
        self.field_class = field_class
        self.alias_class = alias_class
        self.message_class = message_class

        self.exceptions = []
        self.json_files = []
        self.types_by_json = {}
        self.enums_by_json = {}
        self.unions_by_json = {}
        self.aliases_by_json = {}
        self.messages_by_json = {}
        self.logger = logger
        for f in files:
            self.parse_json_file(f)
        self.finalize_parsing()

    def parse_json_file(self, path):
        self.logger.info("Parsing json api file: `%s'" % path)
        self.json_files.append(path)
        self.types_by_json[path] = []
        self.enums_by_json[path] = []
        self.unions_by_json[path] = []
        self.aliases_by_json[path] = []
        self.messages_by_json[path] = {}
        with open(path) as f:
            j = json.load(f)
            for k in j["services"]:
                if k in self.services:
                    raise ParseError("Duplicate service `%s'" % k)
                self.services[k] = j["services"][k]
                self.replies.add(self.services[k]["reply"])
                if "events" in self.services[k]:
                    for x in self.services[k]["events"]:
                        self.events.add(x)
                if "stream_msg" in self.services[k]:
                    self.streams.add(self.services[k]["stream_msg"])
            for e in j["enums"]:
                name = e[0]
                value_pairs = e[1:-1]
                enumtype = self.types[e[-1]["enumtype"]]
                enum = self.enum_class(name, value_pairs, enumtype)
                self.enums[enum.name] = enum
                self.logger.debug("Parsed enum: %s" % enum)
                self.enums_by_json[path].append(enum)
            for e in j["enumflags"]:
                name = e[0]
                value_pairs = e[1:-1]
                enumtype = self.types[e[-1]["enumtype"]]
                enum = self.enum_class(name, value_pairs, enumtype)
                self.enums[enum.name] = enum
                self.logger.debug("Parsed enumflag: %s" % enum)
                self.enums_by_json[path].append(enum)
            exceptions = []
            progress = 0
            last_progress = 0
            while True:
                for u in j["unions"]:
                    name = u[0]
                    if name in self.unions:
                        progress = progress + 1
                        continue
                    try:
                        type_pairs = [
                            [self.lookup_type_like_id(t), n] for t, n in u[1:]
                        ]
                        union = self.union_class(name, type_pairs, 0)
                        progress = progress + 1
                    except ParseError as e:
                        exceptions.append(e)
                        continue
                    self.unions[union.name] = union
                    self.logger.debug("Parsed union: %s" % union)
                    self.unions_by_json[path].append(union)
                for t in j["types"]:
                    if t[0] in self.types:
                        progress = progress + 1
                        continue
                    try:
                        type_ = self.struct_type_class(
                            t, self, self.field_class, self.logger
                        )
                        if type_.name in self.types:
                            raise ParseError("Duplicate type `%s'" % type_.name)
                        progress = progress + 1
                    except ParseError as e:
                        exceptions.append(e)
                        continue
                    self.types[type_.name] = type_
                    self.types_by_json[path].append(type_)
                    self.logger.debug("Parsed type: %s" % type_)
                for name, body in j["aliases"].items():
                    if name in self.aliases:
                        progress = progress + 1
                        continue
                    if "length" in body:
                        array_len = body["length"]
                    else:
                        array_len = None
                    try:
                        t = self.lookup_type_like_id(body["type"])
                    except ParseError as e:
                        exceptions.append(e)
                        continue
                    alias = self.alias_class(name, t, array_len)
                    self.aliases[name] = alias
                    self.logger.debug("Parsed alias: %s" % alias)
                    self.aliases_by_json[path].append(alias)
                if not exceptions:
                    # finished parsing
                    break
                if progress <= last_progress:
                    # cannot make forward progress
                    self.exceptions.extend(exceptions)
                    break
                exceptions = []
                last_progress = progress
                progress = 0
            prev_length = len(self.messages)
            processed = []
            while True:
                exceptions = []
                for m in j["messages"]:
                    if m in processed:
                        continue
                    try:
                        msg = self.message_class(self.logger, m, self)
                        if msg.name in self.messages:
                            raise ParseError("Duplicate message `%s'" % msg.name)
                    except ParseError as e:
                        exceptions.append(e)
                        continue
                    self.messages[msg.name] = msg
                    self.messages_by_json[path][msg.name] = msg
                    processed.append(m)
                if prev_length == len(self.messages):
                    # cannot make forward progress ...
                    self.exceptions.extend(exceptions)
                    break
                prev_length = len(self.messages)

    def lookup_type_like_id(self, name):
        mundane_name = remove_magic(name)
        if name in self.types:
            return self.types[name]
        elif name in self.enums:
            return self.enums[name]
        elif name in self.enumflags:
            return self.enumflags[name]
        elif name in self.unions:
            return self.unions[name]
        elif name in self.aliases:
            return self.aliases[name]
        elif mundane_name in self.types:
            return self.types[mundane_name]
        elif mundane_name in self.enums:
            return self.enums[mundane_name]
        elif mundane_name in self.enumflags:
            return self.enumflags[mundane_name]
        elif mundane_name in self.unions:
            return self.unions[mundane_name]
        elif mundane_name in self.aliases:
            return self.aliases[mundane_name]
        raise ParseError(
            "Could not find type, enum or union by magic name `%s' nor by "
            "mundane name `%s'" % (name, mundane_name)
        )

    def is_reply(self, message):
        return message in self.replies

    def is_event(self, message):
        return message in self.events

    def is_stream(self, message):
        return message in self.streams

    def has_stream_msg(self, message):
        return (
            message.name in self.services
            and "stream_msg" in self.services[message.name]
        )

    def get_stream_msg(self, message):
        if not self.has_stream_msg(message):
            return None
        return self.messages[self.services[message.name]["stream_msg"]]

    def get_reply(self, message):
        return self.messages[self.services[message]["reply"]]

    def finalize_parsing(self):
        if len(self.messages) == 0:
            for e in self.exceptions:
                self.logger.warning(e)
        for jn, j in self.messages_by_json.items():
            remove = []
            for n, m in j.items():
                try:
                    if not m.is_reply and not m.is_event and not m.is_stream:
                        try:
                            m.reply = self.get_reply(n)
                            m.reply_is_stream = False
                            m.has_stream_msg = self.has_stream_msg(m)
                            if "stream" in self.services[m.name]:
                                m.reply_is_stream = self.services[m.name]["stream"]
                            if m.has_stream_msg:
                                m.stream_msg = self.get_stream_msg(m)
                            m.reply.request = m
                        except:
                            raise ParseError("Cannot find reply to message `%s'" % n)
                except ParseError as e:
                    self.exceptions.append(e)
                    remove.append(n)

            self.messages_by_json[jn] = {k: v for k, v in j.items() if k not in remove}
