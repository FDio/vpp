#!/usr/bin/env python3

import sys
import argparse
import keyword
import logging
import binascii
import os
from subprocess import Popen, PIPE
import ply.lex as lex
import ply.yacc as yacc

assert sys.version_info >= (3, 5), "Not supported Python version: {}".format(
    sys.version
)
log = logging.getLogger("vppapigen")

# Ensure we don't leave temporary files around
sys.dont_write_bytecode = True

#
# VPP API language
#

# Global dictionary of new types (including enums)
global_types = {}

seen_imports = {}


def global_type_add(name, obj):
    """Add new type to the dictionary of types"""
    type_name = "vl_api_" + name + "_t"
    if type_name in global_types:
        raise KeyError("Attempted redefinition of {!r} with {!r}.".format(name, obj))
    global_types[type_name] = obj


# All your trace are belong to us!
def exception_handler(exception_type, exception, traceback):
    print("%s: %s" % (exception_type.__name__, exception))


#
# Lexer
#
class VPPAPILexer:
    def __init__(self, filename):
        self.filename = filename

    reserved = {
        "service": "SERVICE",
        "rpc": "RPC",
        "returns": "RETURNS",
        "null": "NULL",
        "stream": "STREAM",
        "events": "EVENTS",
        "define": "DEFINE",
        "typedef": "TYPEDEF",
        "enum": "ENUM",
        "enumflag": "ENUMFLAG",
        "typeonly": "TYPEONLY",
        "manual_print": "MANUAL_PRINT",
        "manual_endian": "MANUAL_ENDIAN",
        "dont_trace": "DONT_TRACE",
        "autoreply": "AUTOREPLY",
        "autoendian": "AUTOENDIAN",
        "option": "OPTION",
        "u8": "U8",
        "u16": "U16",
        "u32": "U32",
        "u64": "U64",
        "i8": "I8",
        "i16": "I16",
        "i32": "I32",
        "i64": "I64",
        "f64": "F64",
        "bool": "BOOL",
        "string": "STRING",
        "import": "IMPORT",
        "true": "TRUE",
        "false": "FALSE",
        "union": "UNION",
        "counters": "COUNTERS",
        "paths": "PATHS",
        "units": "UNITS",
        "severity": "SEVERITY",
        "type": "TYPE",
        "description": "DESCRIPTION",
    }

    tokens = ["STRING_LITERAL", "COMMENT", "ID", "NUM"] + list(reserved.values())

    t_ignore_LINE_COMMENT = "//.*"

    def t_FALSE(self, t):
        r"false"
        t.value = False
        return t

    def t_TRUE(self, t):
        r"false"
        t.value = True
        return t

    def t_NUM(self, t):
        r"0[xX][0-9a-fA-F]+|-?\d+\.?\d*"
        base = 16 if t.value.startswith("0x") else 10
        if "." in t.value:
            t.value = float(t.value)
        else:
            t.value = int(t.value, base)
        return t

    def t_ID(self, t):
        r"[a-zA-Z_][a-zA-Z_0-9]*"
        # Check for reserved words
        t.type = VPPAPILexer.reserved.get(t.value, "ID")
        return t

    # C string
    def t_STRING_LITERAL(self, t):
        r"\"([^\\\n]|(\\.))*?\" "
        t.value = str(t.value).replace('"', "")
        return t

    # C or C++ comment (ignore)
    def t_COMMENT(self, t):
        r"(/\*(.|\n)*?\*/)|(//.*)"
        t.lexer.lineno += t.value.count("\n")
        return t

    # Error handling rule
    def t_error(self, t):
        raise ParseError(
            "Illegal character '{}' ({})"
            "in {}: line {}".format(
                t.value[0], hex(ord(t.value[0])), self.filename, t.lexer.lineno
            )
        )

    # Define a rule so we can track line numbers
    def t_newline(self, t):
        r"\n+"
        t.lexer.lineno += len(t.value)

    literals = ":{}[];=.,"

    # A string containing ignored characters (spaces and tabs)
    t_ignore = " \t"


def vla_mark_length_field(block):
    if isinstance(block[-1], Array):
        lengthfield = block[-1].lengthfield
        for b in block:
            if b.fieldname == lengthfield:
                b.is_lengthfield = True


def vla_is_last_check(name, block):
    vla = False
    for i, b in enumerate(block):
        if isinstance(b, Array) and b.vla:
            vla = True
            if i + 1 < len(block):
                raise ValueError(
                    'VLA field "{}" must be the last field in message "{}"'.format(
                        b.fieldname, name
                    )
                )
        elif b.fieldtype.startswith("vl_api_"):
            if global_types[b.fieldtype].vla:
                vla = True
                if i + 1 < len(block):
                    raise ValueError(
                        'VLA field "{}" must be the last '
                        'field in message "{}"'.format(b.fieldname, name)
                    )
        elif b.fieldtype == "string" and b.length == 0:
            vla = True
            if i + 1 < len(block):
                raise ValueError(
                    'VLA field "{}" must be the last '
                    'field in message "{}"'.format(b.fieldname, name)
                )
    return vla


class Processable:
    type = "<Invalid>"

    def process(self, result):  # -> Dict
        result[self.type].append(self)


class Service(Processable):
    type = "Service"

    def __init__(self, caller, reply, events=None, stream_message=None, stream=False):
        self.caller = caller
        self.reply = reply
        self.stream = stream
        self.stream_message = stream_message
        self.events = [] if events is None else events


class Typedef(Processable):
    type = "Typedef"

    def __init__(self, name, flags, block):
        self.name = name
        self.flags = flags
        self.block = block
        self.crc = str(block).encode()
        self.manual_print = False
        self.manual_endian = False
        for f in flags:
            if f == "manual_print":
                self.manual_print = True
            elif f == "manual_endian":
                self.manual_endian = True
        global_type_add(name, self)

        self.vla = vla_is_last_check(name, block)
        vla_mark_length_field(self.block)

    def process(self, result):
        result["types"].append(self)

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Using(Processable):
    type = "Using"

    def __init__(self, name, flags, alias):
        self.name = name
        self.vla = False
        self.block = []
        self.manual_print = True
        self.manual_endian = True

        self.manual_print = False
        self.manual_endian = False
        for f in flags:
            if f == "manual_print":
                self.manual_print = True
            elif f == "manual_endian":
                self.manual_endian = True

        if isinstance(alias, Array):
            a = {"type": alias.fieldtype, "length": alias.length}
        else:
            a = {"type": alias.fieldtype}
        self.alias = a
        self.using = alias

        #
        # Should have been:
        #  self.crc = str(alias).encode()
        # but to be backwards compatible use the block ([])
        #
        self.crc = str(self.block).encode()
        global_type_add(name, self)

    def process(self, result):  # -> Dict
        result["types"].append(self)

    def __repr__(self):
        return self.name + str(self.alias)


class Union(Processable):
    type = "Union"

    def __init__(self, name, flags, block):
        self.manual_print = False
        self.manual_endian = False
        self.name = name

        for f in flags:
            if f == "manual_print":
                self.manual_print = True
            elif f == "manual_endian":
                self.manual_endian = True

        self.block = block
        self.crc = str(block).encode()
        self.vla = vla_is_last_check(name, block)

        global_type_add(name, self)

    def process(self, result):
        result["types"].append(self)

    def __repr__(self):
        return str(self.block)


class Define(Processable):
    type = "Define"

    def __init__(self, name, flags, block, comment=None):
        self.name = name
        self.flags = flags
        self.block = block
        self.dont_trace = False
        self.manual_print = False
        self.manual_endian = False
        self.autoreply = False
        self.autoendian = 0
        self.options = {}
        self.comment = comment
        for f in flags:
            if f == "dont_trace":
                self.dont_trace = True
            elif f == "manual_print":
                self.manual_print = True
            elif f == "manual_endian":
                self.manual_endian = True
            elif f == "autoreply":
                self.autoreply = True
            elif f == "autoendian":
                self.autoendian = 1

        remove = []
        for b in block:
            if isinstance(b, Option):
                self.options[b.option] = b.value
                remove.append(b)

        block = [x for x in block if x not in remove]
        self.block = block
        self.vla = vla_is_last_check(name, block)
        vla_mark_length_field(self.block)

        self.crc = str(block).encode()

    def autoreply_block(self, name, parent):
        block = [Field("u32", "context"), Field("i32", "retval")]
        # inherit the parent's options
        for k, v in parent.options.items():
            block.append(Option(k, v))
        return Define(name + "_reply", [], block)

    def process(self, result):  # -> Dict
        tname = self.__class__.__name__
        result[tname].append(self)
        if self.autoreply:
            result[tname].append(self.autoreply_block(self.name, self))

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Enum(Processable):
    type = "Enum"

    def __init__(self, name, block, enumtype="u32"):
        self.name = name
        self.enumtype = enumtype
        self.vla = False
        self.manual_print = False

        count = -1
        block2 = []
        block3 = []
        bc_set = False

        for b in block:
            if "value" in b:
                count = b["value"]
            else:
                count += 1
            block2.append([b["id"], count])
            try:
                if b["option"]["backwards_compatible"]:
                    pass
                bc_set = True
            except KeyError:
                block3.append([b["id"], count])
                if bc_set:
                    raise ValueError(
                        "Backward compatible enum must "
                        "be last {!r} {!r}".format(name, b["id"])
                    )
        self.block = block2
        self.crc = str(block3).encode()
        global_type_add(name, self)

    def process(self, result):
        result["types"].append(self)

    def __repr__(self):
        return self.name + str(self.block)


class EnumFlag(Enum):
    type = "EnumFlag"

    def __init__(self, name, block, enumtype="u32"):
        super(EnumFlag, self).__init__(name, block, enumtype)

        for b in self.block:
            if bin(b[1])[2:].count("1") > 1:
                raise TypeError(
                    "%s is not a flag enum.  No element in a "
                    "flag enum may have more than a "
                    "single bit set." % self.name
                )


class Import(Processable):
    type = "Import"
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if args[0] not in seen_imports:
            instance = super().__new__(cls)
            instance._initialized = False
            seen_imports[args[0]] = instance

        return seen_imports[args[0]]

    def __init__(self, filename, revision):
        if self._initialized:
            return
        self.filename = filename
        # Deal with imports
        parser = VPPAPI(filename=filename, revision=revision)
        dirlist = dirlist_get()
        f = filename
        for dir in dirlist:
            f = os.path.join(dir, filename)
            if os.path.exists(f):
                break
        self.result = parser.parse_filename(f, None)
        self._initialized = True

    def __repr__(self):
        return self.filename


class Option(Processable):
    type = "Option"

    def __init__(self, option, value=None):
        self.option = option
        self.value = value
        self.crc = str(option).encode()

    def process(self, result):  # -> Dict
        result[self.type][self.option] = self.value

    def __repr__(self):
        return str(self.option)

    def __getitem__(self, index):
        return self.option[index]


class Array(Processable):
    type = "Array"

    def __init__(self, fieldtype, name, length, modern_vla=False):
        self.fieldtype = fieldtype
        self.fieldname = name
        self.modern_vla = modern_vla
        if type(length) is str:
            self.lengthfield = length
            self.length = 0
            self.vla = True
        else:
            self.length = length
            self.lengthfield = None
            self.vla = False

    def __repr__(self):
        return str([self.fieldtype, self.fieldname, self.length, self.lengthfield])


class Field(Processable):
    type = "Field"

    def __init__(self, fieldtype, name, limit=None):
        # limit field has been expanded to an options dict.

        self.fieldtype = fieldtype
        self.is_lengthfield = False

        if self.fieldtype == "string":
            raise ValueError("The string type {!r} is an " "array type ".format(name))

        if name in keyword.kwlist:
            raise ValueError(
                "Fieldname {!r} is a python keyword and is not "
                "accessible via the python API. ".format(name)
            )
        self.fieldname = name
        self.limit = limit

    def __repr__(self):
        return str([self.fieldtype, self.fieldname])


class Counter(Processable):
    type = "Counter"

    def __init__(self, path, counter):
        self.name = path
        self.block = counter

    def process(self, result):  # -> Dict
        result["Counters"].append(self)


class Paths(Processable):
    type = "Paths"

    def __init__(self, pathset):
        self.paths = pathset

    def __repr__(self):
        return "%s(paths=%s)" % (self.__class__.__name__, self.paths)


class Coord:
    """Coordinates of a syntactic element. Consists of:
    - File name
    - Line number
    - (optional) column number, for the Lexer
    """

    __slots__ = ("file", "line", "column", "__weakref__")

    def __init__(self, file, line, column=None):
        self.file = file
        self.line = line
        self.column = column

    def __str__(self):
        str = "%s:%s" % (self.file, self.line)
        if self.column:
            str += ":%s" % self.column
        return str


class ParseError(Exception):
    pass


#
# Grammar rules
#
class VPPAPIParser:
    tokens = VPPAPILexer.tokens

    def __init__(self, filename, logger, revision=None):
        self.filename = filename
        self.logger = logger
        self.fields = []
        self.revision = revision
        self.last_comment = None

    def _parse_error(self, msg, coord):
        raise ParseError("%s: %s" % (coord, msg))

    def _parse_warning(self, msg, coord):
        if self.logger:
            self.logger.warning("%s: %s" % (coord, msg))

    def _coord(self, lineno, column=None):
        return Coord(file=self.filename, line=lineno, column=column)

    def _token_coord(self, p, token_idx):
        """Returns the coordinates for the YaccProduction object 'p' indexed
        with 'token_idx'. The coordinate includes the 'lineno' and
        'column'. Both follow the lex semantic, starting from 1.
        """
        last_cr = p.lexer.lexdata.rfind("\n", 0, p.lexpos(token_idx))
        if last_cr < 0:
            last_cr = -1
        column = p.lexpos(token_idx) - (last_cr)
        return self._coord(p.lineno(token_idx), column)

    def p_slist(self, p):
        """slist : stmt
        | slist stmt"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_stmt(self, p):
        """stmt : define
        | typedef
        | option
        | import
        | enum
        | enumflag
        | union
        | service
        | paths
        | comment
        | counters"""
        p[0] = p[1]

    def p_import(self, p):
        """import : IMPORT STRING_LITERAL ';'"""
        p[0] = Import(p[2], revision=self.revision)

    def p_path_elements(self, p):
        """path_elements : path_element
        | path_elements path_element"""
        if len(p) == 2:
            p[0] = p[1]
        else:
            if type(p[1]) is dict:
                p[0] = [p[1], p[2]]
            else:
                p[0] = p[1] + [p[2]]

    def p_path_element(self, p):
        """path_element : STRING_LITERAL STRING_LITERAL ';'"""
        p[0] = {"path": p[1], "counter": p[2]}

    def p_paths(self, p):
        """paths : PATHS '{' path_elements '}' ';'"""
        p[0] = Paths(p[3])

    def p_counters(self, p):
        """counters : COUNTERS ID '{' counter_elements '}' ';'"""
        p[0] = Counter(p[2], p[4])

    def p_counter_elements(self, p):
        """counter_elements : counter_element
        | counter_elements counter_element"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            if type(p[1]) is dict:
                p[0] = [p[1], p[2]]
            else:
                p[0] = p[1] + [p[2]]

    def p_counter_element(self, p):
        """counter_element : ID '{' counter_statements '}' ';'"""
        p[0] = {**{"name": p[1]}, **p[3]}

    def p_counter_statements(self, p):
        """counter_statements : counter_statement
        | counter_statements counter_statement"""
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = {**p[1], **p[2]}

    def p_counter_statement(self, p):
        """counter_statement : SEVERITY ID ';'
        | UNITS STRING_LITERAL ';'
        | DESCRIPTION STRING_LITERAL ';'
        | TYPE ID ';'"""
        p[0] = {p[1]: p[2]}

    def p_service(self, p):
        """service : SERVICE '{' service_statements '}' ';'"""
        p[0] = p[3]

    def p_service_statements(self, p):
        """service_statements : service_statement
        | service_statements service_statement"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_service_statement(self, p):
        """service_statement : RPC ID RETURNS NULL ';'
        | RPC ID RETURNS ID ';'
        | RPC ID RETURNS STREAM ID ';'
        | RPC ID RETURNS ID EVENTS event_list ';'"""
        if p[2] == p[4]:
            # Verify that caller and reply differ
            self._parse_error(
                "Reply ID ({}) should not be equal to Caller ID".format(p[2]),
                self._token_coord(p, 1),
            )
        if len(p) == 8:
            p[0] = Service(p[2], p[4], p[6])
        elif len(p) == 7:
            p[0] = Service(p[2], p[5], stream=True)
        else:
            p[0] = Service(p[2], p[4])

    def p_service_statement2(self, p):
        """service_statement : RPC ID RETURNS ID STREAM ID ';'"""
        p[0] = Service(p[2], p[4], stream_message=p[6], stream=True)

    def p_event_list(self, p):
        """event_list : events
        | event_list events"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_event(self, p):
        """events : ID
        | ID ','"""
        p[0] = p[1]

    def p_enum(self, p):
        """enum : ENUM ID '{' enum_statements '}' ';'"""
        p[0] = Enum(p[2], p[4])

    def p_enum_type(self, p):
        """enum : ENUM ID ':' enum_size '{' enum_statements '}' ';'"""
        if len(p) == 9:
            p[0] = Enum(p[2], p[6], enumtype=p[4])
        else:
            p[0] = Enum(p[2], p[4])

    def p_enumflag(self, p):
        """enumflag : ENUMFLAG ID '{' enum_statements '}' ';'"""
        p[0] = EnumFlag(p[2], p[4])

    def p_enumflag_type(self, p):
        """enumflag : ENUMFLAG ID ':' enumflag_size '{' enum_statements '}' ';'"""  # noqa : E502
        if len(p) == 9:
            p[0] = EnumFlag(p[2], p[6], enumtype=p[4])
        else:
            p[0] = EnumFlag(p[2], p[4])

    def p_enum_size(self, p):
        """enum_size : U8
        | U16
        | U32
        | I8
        | I16
        | I32"""
        p[0] = p[1]

    def p_enumflag_size(self, p):
        """enumflag_size : U8
        | U16
        | U32"""
        p[0] = p[1]

    def p_define(self, p):
        """define : DEFINE ID '{' block_statements_opt '}' ';'"""
        self.fields = []
        p[0] = Define(p[2], [], p[4], self.last_comment)
        self.last_comment = None

    def p_define_flist(self, p):
        """define : flist DEFINE ID '{' block_statements_opt '}' ';'"""
        # Legacy typedef
        if "typeonly" in p[1]:
            self._parse_error(
                "legacy typedef. use typedef: {} {}[{}];".format(p[1], p[2], p[4]),
                self._token_coord(p, 1),
            )
        else:
            p[0] = Define(p[3], p[1], p[5], self.last_comment)
            self.last_comment = None

    def p_flist(self, p):
        """flist : flag
        | flist flag"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_flag(self, p):
        """flag : MANUAL_PRINT
        | MANUAL_ENDIAN
        | DONT_TRACE
        | TYPEONLY
        | AUTOENDIAN
        | AUTOREPLY"""
        if len(p) == 1:
            return
        p[0] = p[1]

    def p_typedef(self, p):
        """typedef : TYPEDEF ID '{' block_statements_opt '}' ';'"""
        p[0] = Typedef(p[2], [], p[4])

    def p_typedef_flist(self, p):
        """typedef : flist TYPEDEF ID '{' block_statements_opt '}' ';'"""
        p[0] = Typedef(p[3], p[1], p[5])

    def p_typedef_alias(self, p):
        """typedef : TYPEDEF declaration"""
        p[0] = Using(p[2].fieldname, [], p[2])

    def p_typedef_alias_flist(self, p):
        """typedef : flist TYPEDEF declaration"""
        p[0] = Using(p[3].fieldname, p[1], p[3])

    def p_block_statements_opt(self, p):
        """block_statements_opt : block_statements"""
        p[0] = p[1]

    def p_block_statements(self, p):
        """block_statements : block_statement
        | block_statements block_statement"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_block_statement(self, p):
        """block_statement : declaration
        | option"""
        p[0] = p[1]

    def p_enum_statements(self, p):
        """enum_statements : enum_statement
        | enum_statements enum_statement"""
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_enum_statement(self, p):
        """enum_statement : ID '=' NUM ','
        | ID ','
        | ID '[' field_options ']' ','
        | ID '=' NUM '[' field_options ']' ','"""
        if len(p) == 3:
            p[0] = {"id": p[1]}
        elif len(p) == 5:
            p[0] = {"id": p[1], "value": p[3]}
        elif len(p) == 6:
            p[0] = {"id": p[1], "option": p[3]}
        elif len(p) == 8:
            p[0] = {"id": p[1], "value": p[3], "option": p[5]}
        else:
            self._parse_error("ERROR", self._token_coord(p, 1))

    def p_field_options(self, p):
        """field_options : field_option
        | field_options field_option"""
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = {**p[1], **p[2]}

    def p_field_option(self, p):
        """field_option : ID
        | ID '=' assignee ','
        | ID '=' assignee

        """
        if len(p) == 2:
            p[0] = {p[1]: None}
        else:
            p[0] = {p[1]: p[3]}

    def p_variable_name(self, p):
        """variable_name : ID
        | TYPE
        | SEVERITY
        | DESCRIPTION
        | COUNTERS
        | PATHS
        """
        p[0] = p[1]

    def p_comment(self, p):
        """comment : COMMENT"""
        self.last_comment = p[1]
        p[0] = []

    def p_declaration(self, p):
        """declaration : type_specifier variable_name ';'
        | type_specifier variable_name '[' field_options ']' ';'
        """
        if len(p) == 7:
            p[0] = Field(p[1], p[2], p[4])
        elif len(p) == 4:
            p[0] = Field(p[1], p[2])
        else:
            self._parse_error("ERROR", self._token_coord(p, 1))
        self.fields.append(p[2])

    def p_declaration_array_vla(self, p):
        """declaration : type_specifier variable_name '[' ']' ';'"""
        p[0] = Array(p[1], p[2], 0, modern_vla=True)

    def p_declaration_array(self, p):
        """declaration : type_specifier variable_name '[' NUM ']' ';'
        | type_specifier variable_name '[' ID ']' ';'"""

        if len(p) != 7:
            return self._parse_error(
                "array: %s" % p.value, self._coord(lineno=p.lineno)
            )

        # Make this error later
        if type(p[4]) is int and p[4] == 0:
            # XXX: Line number is wrong
            self._parse_warning(
                "Old Style VLA: {} {}[{}];".format(p[1], p[2], p[4]),
                self._token_coord(p, 1),
            )

        if type(p[4]) is str and p[4] not in self.fields:
            # Verify that length field exists
            self._parse_error(
                "Missing length field: {} {}[{}];".format(p[1], p[2], p[4]),
                self._token_coord(p, 1),
            )
        p[0] = Array(p[1], p[2], p[4])

    def p_option(self, p):
        """option : OPTION ID '=' assignee ';'
        | OPTION ID ';'"""
        if len(p) == 4:
            p[0] = Option(p[2])
        else:
            p[0] = Option(p[2], p[4])

    def p_assignee(self, p):
        """assignee : NUM
        | TRUE
        | FALSE
        | STRING_LITERAL"""
        p[0] = p[1]

    def p_type_specifier(self, p):
        """type_specifier : U8
        | U16
        | U32
        | U64
        | I8
        | I16
        | I32
        | I64
        | F64
        | BOOL
        | STRING"""
        p[0] = p[1]

    # Do a second pass later to verify that user defined types are defined
    def p_typedef_specifier(self, p):
        """type_specifier : ID"""
        if p[1] not in global_types:
            self._parse_error(
                "Undefined type: {}".format(p[1]), self._token_coord(p, 1)
            )
        p[0] = p[1]

    def p_union(self, p):
        """union : UNION ID '{' block_statements_opt '}' ';'"""
        p[0] = Union(p[2], [], p[4])

    def p_union_flist(self, p):
        """union : flist UNION ID '{' block_statements_opt '}' ';'"""
        p[0] = Union(p[3], p[1], p[5])

    # Error rule for syntax errors
    def p_error(self, p):
        if p:
            if p.type == "COMMENT":
                self.parser.errok()
                return
            self._parse_error("before: %s" % p.value, self._coord(lineno=p.lineno))
        else:
            self._parse_error("At end of input", self.filename)

    def build(self, **kwargs):
        self.parser = yacc.yacc(module=self, **kwargs)


class VPPAPI:
    def __init__(self, debug=False, filename="", logger=None, revision=None):
        self.lexer = lex.lex(module=VPPAPILexer(filename), debug=debug)
        self.parser = VPPAPIParser(filename, logger, revision=revision)
        self.parser.build(write_tables=False, debug=debug)
        self.logger = logger
        self.revision = revision
        self.filename = filename

    def parse_string(self, code, debug=0, lineno=1):
        self.lexer.lineno = lineno
        return self.parser.parser.parse(code, lexer=self.lexer, debug=debug)

    def parse_fd(self, fd, debug=0):
        data = fd.read()
        return self.parse_string(data, debug=debug)

    def parse_filename(self, filename, debug=0):
        if self.revision:
            git_show = "git show {}:{}".format(self.revision, filename)
            proc = Popen(git_show.split(), stdout=PIPE, encoding="utf-8")
            try:
                data, errs = proc.communicate()
                if proc.returncode != 0:
                    print(
                        "File not found: {}:{}".format(self.revision, filename),
                        file=sys.stderr,
                    )
                    sys.exit(2)
                return self.parse_string(data, debug=debug)
            except Exception:
                sys.exit(3)
        else:
            try:
                with open(filename, encoding="utf-8") as fd:
                    return self.parse_fd(fd, None)
            except FileNotFoundError:
                print("File not found: {}".format(filename), file=sys.stderr)
                sys.exit(2)

    def process(self, objs):
        s = {}
        s["Option"] = {}
        s["Define"] = []
        s["Service"] = []
        s["types"] = []
        s["Import"] = []
        s["Counters"] = []
        s["Paths"] = []
        crc = 0
        for o in objs:
            try:
                crc = binascii.crc32(o.crc, crc) & 0xFFFFFFFF
            except AttributeError:
                pass

            if type(o) is list:
                for o2 in o:
                    if isinstance(o2, Service):
                        o2.process(s)
            else:
                o.process(s)

        msgs = {d.name: d for d in s["Define"]}
        svcs = {s.caller: s for s in s["Service"]}
        replies = {s.reply: s for s in s["Service"]}
        seen_services = {}

        s["file_crc"] = crc

        for service in svcs:
            if service not in msgs:
                raise ValueError(
                    "Service definition refers to unknown message"
                    " definition: {}".format(service)
                )
            if svcs[service].reply != "null" and svcs[service].reply not in msgs:
                raise ValueError(
                    "Service definition refers to unknown message"
                    " definition in reply: {}".format(svcs[service].reply)
                )
            if service in replies:
                raise ValueError(
                    "Service definition refers to message"
                    " marked as reply: {}".format(service)
                )
            for event in svcs[service].events:
                if event not in msgs:
                    raise ValueError(
                        "Service definition refers to unknown "
                        "event: {} in message: {}".format(event, service)
                    )
                seen_services[event] = True

        # Create services implicitly
        for d in msgs:
            if d in seen_services:
                continue
            if d.endswith("_reply"):
                if d[:-6] in svcs:
                    continue
                if d[:-6] not in msgs:
                    raise ValueError("{} missing calling message".format(d))
                continue
            if d.endswith("_dump"):
                if d in svcs:
                    continue
                if d[:-5] + "_details" in msgs:
                    s["Service"].append(Service(d, d[:-5] + "_details", stream=True))
                else:
                    raise ValueError("{} missing details message".format(d))
                continue

            if d.endswith("_details"):
                if d[:-8] + "_get" in msgs:
                    if d[:-8] + "_get" in svcs:
                        continue
                    raise ValueError(
                        "{} should be in a stream service".format(d[:-8] + "_get")
                    )
                if d[:-8] + "_dump" in msgs:
                    continue
                raise ValueError("{} missing dump or get message".format(d))

            if d in svcs:
                continue
            if d + "_reply" in msgs:
                s["Service"].append(Service(d, d + "_reply"))
            else:
                raise ValueError(
                    "{} missing reply message ({}) or service definition".format(
                        d, d + "_reply"
                    )
                )

        return s

    def process_imports(self, objs, in_import, result):  # -> List
        for o in objs:
            # Only allow the following object types from imported file
            if in_import and not isinstance(o, (Enum, Import, Typedef, Union, Using)):
                continue
            if isinstance(o, Import):
                result.append(o)
                result = self.process_imports(o.result, True, result)
            else:
                result.append(o)
        return result


# Add message ids to each message.
def add_msg_id(s):
    for o in s:
        o.block.insert(0, Field("u16", "_vl_msg_id"))
    return s


dirlist = []


def dirlist_add(dirs):
    global dirlist
    if dirs:
        dirlist = dirlist + dirs


def dirlist_get():
    return dirlist


def foldup_blocks(block, crc):
    for b in block:
        # Look up CRC in user defined types
        if b.fieldtype.startswith("vl_api_"):
            # Recursively
            t = global_types[b.fieldtype]
            try:
                crc = binascii.crc32(t.crc, crc) & 0xFFFFFFFF
                crc = foldup_blocks(t.block, crc)
            except AttributeError:
                pass
    return crc


def foldup_crcs(s):
    for f in s:
        f.crc = foldup_blocks(f.block, binascii.crc32(f.crc) & 0xFFFFFFFF)


def run_vppapigen(
    input_file=None,
    output=sys.stdout,
    includedir=None,
    debug=False,
    show_name=None,
    output_module="C",
    outputdir=None,
    pluginpath="",
    git_revision=None,
):
    # reset globals
    dirlist.clear()
    global_types.clear()
    seen_imports.clear()

    dirlist_add(includedir)
    if not debug:
        sys.excepthook = exception_handler

    # Filename
    if show_name:
        filename = show_name[0]
    elif input_file:
        filename = input_file
    else:
        filename = ""

    if debug:
        logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
    else:
        logging.basicConfig()

    #
    # Generate representation
    #
    from importlib.machinery import SourceFileLoader

    # Default path
    pluginpath = ""
    if not pluginpath:
        cand = []
        cand.append(os.path.dirname(os.path.realpath(__file__)))
        cand.append(os.path.dirname(os.path.realpath(__file__)) + "/../share/vpp/")
        for c in cand:
            c += "/"
            if os.path.isfile("{}vppapigen_{}.py".format(c, output_module.lower())):
                pluginpath = c
                break
    else:
        pluginpath = pluginpath + "/"
    if pluginpath == "":
        log.exception("Output plugin not found")
        return 1
    module_path = "{}vppapigen_{}.py".format(pluginpath, output_module.lower())

    try:
        plugin = SourceFileLoader(output_module, module_path).load_module()
    except Exception as err:
        log.exception("Error importing output plugin: %s, %s", module_path, err)
        return 1

    parser = VPPAPI(debug=debug, filename=filename, logger=log, revision=git_revision)

    try:
        if not input_file:
            parsed_objects = parser.parse_fd(sys.stdin, log)
        else:
            parsed_objects = parser.parse_filename(input_file, log)
    except ParseError as e:
        print("Parse error: ", e, file=sys.stderr)
        sys.exit(1)

    # Build a list of objects. Hash of lists.
    result = []

    # if the variable is not set in the plugin, assume it to be false.
    try:
        plugin.process_imports
    except AttributeError:
        plugin.process_imports = False

    if plugin.process_imports:
        result = parser.process_imports(parsed_objects, False, result)
        s = parser.process(result)
    else:
        s = parser.process(parsed_objects)
        imports = parser.process_imports(parsed_objects, False, result)
        s["imported"] = parser.process(imports)

    # Add msg_id field
    s["Define"] = add_msg_id(s["Define"])

    # Fold up CRCs
    foldup_crcs(s["Define"])

    #
    # Debug
    if debug:
        import pprint

        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        for t in s["Define"]:
            pp.pprint([t.name, t.flags, t.block])
        for t in s["types"]:
            pp.pprint([t.name, t.block])

    result = plugin.run(outputdir, filename, s)
    if result:
        if isinstance(output, str):
            with open(output, "w", encoding="UTF-8") as f:
                print(result, file=f)
        else:
            print(result, file=output)
    else:
        log.exception("Running plugin failed: %s %s", filename, result)
        return 1
    return 0


def run_kw_vppapigen(kwargs):
    return run_vppapigen(**kwargs)


#
# Main
#
def main():
    if sys.version_info < (
        3,
        5,
    ):
        log.exception(
            "vppapigen requires a supported version of python. "
            "Please use version 3.5 or greater. "
            "Using %s",
            sys.version,
        )
        return 1

    cliparser = argparse.ArgumentParser(description="VPP API generator")
    cliparser.add_argument("--pluginpath", default="")
    cliparser.add_argument("--includedir", action="append")
    cliparser.add_argument("--outputdir", action="store")
    cliparser.add_argument("--input")
    cliparser.add_argument(
        "--output",
        nargs="?",
        type=argparse.FileType("w", encoding="UTF-8"),
        default=sys.stdout,
    )

    cliparser.add_argument("output_module", nargs="?", default="C")
    cliparser.add_argument("--debug", action="store_true")
    cliparser.add_argument("--show-name", nargs=1)
    cliparser.add_argument(
        "--git-revision", help="Git revision to use for opening files"
    )
    args = cliparser.parse_args()

    return run_vppapigen(
        includedir=args.includedir,
        debug=args.debug,
        outputdir=args.outputdir,
        show_name=args.show_name,
        input_file=args.input,
        output_module=args.output_module,
        pluginpath=args.pluginpath,
        git_revision=args.git_revision,
        output=args.output,
    )


if __name__ == "__main__":
    sys.exit(main())
