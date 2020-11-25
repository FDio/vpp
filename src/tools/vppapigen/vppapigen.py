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

assert sys.version_info >= (3, 5), \
    "Not supported Python version: {}".format(sys.version)
log = logging.getLogger('vppapigen')

# Ensure we don't leave temporary files around
sys.dont_write_bytecode = True

#
# VPP API language
#

# Global dictionary of new types (including enums)
global_types = {}

seen_imports = {}


def global_type_add(name, obj):
    '''Add new type to the dictionary of types '''
    type_name = 'vl_api_' + name + '_t'
    if type_name in global_types:
        raise KeyError("Attempted redefinition of {!r} with {!r}.".format(
            name, obj))
    global_types[type_name] = obj


# All your trace are belong to us!
def exception_handler(exception_type, exception, traceback):
    print("%s: %s" % (exception_type.__name__, exception))


#
# Lexer
#
class VPPAPILexer(object):
    def __init__(self, filename):
        self.filename = filename

    reserved = {
        'service': 'SERVICE',
        'rpc': 'RPC',
        'returns': 'RETURNS',
        'null': 'NULL',
        'stream': 'STREAM',
        'events': 'EVENTS',
        'define': 'DEFINE',
        'typedef': 'TYPEDEF',
        'enum': 'ENUM',
        'enumflag': 'ENUMFLAG',
        'typeonly': 'TYPEONLY',
        'manual_print': 'MANUAL_PRINT',
        'manual_endian': 'MANUAL_ENDIAN',
        'dont_trace': 'DONT_TRACE',
        'autoreply': 'AUTOREPLY',
        'option': 'OPTION',
        'u8': 'U8',
        'u16': 'U16',
        'u32': 'U32',
        'u64': 'U64',
        'i8': 'I8',
        'i16': 'I16',
        'i32': 'I32',
        'i64': 'I64',
        'f64': 'F64',
        'bool': 'BOOL',
        'string': 'STRING',
        'import': 'IMPORT',
        'true': 'TRUE',
        'false': 'FALSE',
        'union': 'UNION',
        'counters': 'COUNTERS',
        'paths': 'PATHS',
        'units': 'UNITS',
        'severity': 'SEVERITY',
        'type': 'TYPE',
        'description': 'DESCRIPTION',
    }

    tokens = ['STRING_LITERAL',
              'ID', 'NUM'] + list(reserved.values())

    t_ignore_LINE_COMMENT = '//.*'

    def t_FALSE(self, t):
        r'false'
        t.value = False
        return t

    def t_TRUE(self, t):
        r'false'
        t.value = True
        return t

    def t_NUM(self, t):
        r'0[xX][0-9a-fA-F]+|-?\d+\.?\d*'
        base = 16 if t.value.startswith('0x') else 10
        if '.' in t.value:
            t.value = float(t.value)
        else:
            t.value = int(t.value, base)
        return t

    def t_ID(self, t):
        r'[a-zA-Z_][a-zA-Z_0-9]*'
        # Check for reserved words
        t.type = VPPAPILexer.reserved.get(t.value, 'ID')
        return t

    # C string
    def t_STRING_LITERAL(self, t):
        r'\"([^\\\n]|(\\.))*?\"'
        t.value = str(t.value).replace("\"", "")
        return t

    # C or C++ comment (ignore)
    def t_comment(self, t):
        r'(/\*(.|\n)*?\*/)|(//.*)'
        t.lexer.lineno += t.value.count('\n')

    # Error handling rule
    def t_error(self, t):
        raise ParseError("Illegal character '{}' ({})"
                         "in {}: line {}".format(t.value[0],
                                                 hex(ord(t.value[0])),
                                                 self.filename,
                                                 t.lexer.lineno))

    # Define a rule so we can track line numbers
    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    literals = ":{}[];=.,"

    # A string containing ignored characters (spaces and tabs)
    t_ignore = ' \t'


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
                    'VLA field "{}" must be the last field in message "{}"'
                    .format(b.fieldname, name))
        elif b.fieldtype.startswith('vl_api_'):
            if global_types[b.fieldtype].vla:
                vla = True
                if i + 1 < len(block):
                    raise ValueError(
                        'VLA field "{}" must be the last '
                        'field in message "{}"'
                        .format(b.fieldname, name))
        elif b.fieldtype == 'string' and b.length == 0:
            vla = True
            if i + 1 < len(block):
                raise ValueError(
                    'VLA field "{}" must be the last '
                    'field in message "{}"'
                    .format(b.fieldname, name))
    return vla


class Processable:
    type = "<Invalid>"

    def process(self, result):  # -> Dict
        result[self.type].append(self)


class Service(Processable):
    type = 'Service'

    def __init__(self, caller, reply, events=None, stream_message=None,
                 stream=False):
        self.caller = caller
        self.reply = reply
        self.stream = stream
        self.stream_message = stream_message
        self.events = [] if events is None else events


class Typedef(Processable):
    type = 'Typedef'

    def __init__(self, name, flags, block):
        self.name = name
        self.flags = flags
        self.block = block
        self.crc = str(block).encode()
        self.manual_print = False
        self.manual_endian = False
        for f in flags:
            if f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True
        global_type_add(name, self)

        self.vla = vla_is_last_check(name, block)
        vla_mark_length_field(self.block)

    def process(self, result):
        result['types'].append(self)

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Using(Processable):
    type = 'Using'

    def __init__(self, name, flags, alias):
        self.name = name
        self.vla = False
        self.block = []
        self.manual_print = True
        self.manual_endian = True

        self.manual_print = False
        self.manual_endian = False
        for f in flags:
            if f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True

        if isinstance(alias, Array):
            a = {'type': alias.fieldtype,
                 'length': alias.length}
        else:
            a = {'type': alias.fieldtype}
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
        result['types'].append(self)

    def __repr__(self):
        return self.name + str(self.alias)


class Union(Processable):
    type = 'Union'

    def __init__(self, name, flags, block):
        self.manual_print = False
        self.manual_endian = False
        self.name = name

        for f in flags:
            if f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True

        self.block = block
        self.crc = str(block).encode()
        self.vla = vla_is_last_check(name, block)

        global_type_add(name, self)

    def process(self, result):
        result['types'].append(self)

    def __repr__(self):
        return str(self.block)


class Define():
    def __init__(self, name, flags, block):
        self.name = name
        self.type = 'Define'
        self.flags = flags
        self.block = block
        self.dont_trace = False
        self.manual_print = False
        self.manual_endian = False
        self.autoreply = False
        self.singular = False
        self.options = {}
        for f in flags:
            if f == 'dont_trace':
                self.dont_trace = True
            elif f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True
            elif f == 'autoreply':
                self.autoreply = True

        remove = []
        for b in block:
            if isinstance(b, Option):
                if b[1] == 'singular' and b[2] == 'true':
                    self.singular = True
                else:
                    self.options[b.option] = b.value
                remove.append(b)

        block = [x for x in block if x not in remove]
        self.block = block
        self.vla = vla_is_last_check(name, block)
        vla_mark_length_field(self.block)

        self.crc = str(block).encode()

    def autoreply_block(self, name, parent):
        block = [Field('u32', 'context'),
                 Field('i32', 'retval')]
        # inherit the parent's options
        for k, v in parent.options.items():
            block.append(Option(k, v))
        return Define(name + '_reply', [], block)

    def process(self, result):  # -> Dict
        tname = self.__class__.__name__
        result[tname].append(self)
        if self.autoreply:
            result[tname].append(self.autoreply_block(self.name, self))

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Enum(Processable):
    type = 'Enum'

    def __init__(self, name, block, enumtype='u32'):
        self.name = name
        self.enumtype = enumtype
        self.vla = False
        self.manual_print = False

        count = 0
        block2 = []
        block3 = []
        bc_set = False

        for b in block:
            if 'value' in b:
                count = b['value']
            else:
                count += 1
            block2.append([b['id'], count])
            try:
                if b['option']['backwards_compatible']:
                    pass
                bc_set = True
            except KeyError:
                block3.append([b['id'], count])
                if bc_set:
                    raise ValueError("Backward compatible enum must "
                                     "be last {!r} {!r}"
                                     .format(name, b['id']))
        self.block = block2
        self.crc = str(block3).encode()
        global_type_add(name, self)

    def process(self, result):
        result['types'].append(self)

    def __repr__(self):
        return self.name + str(self.block)


class EnumFlag(Enum):
    type = 'EnumFlag'


class Import(Processable):
    type = 'Import'
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
    type = 'Option'

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


class Array():
    type = 'Array'

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
        return str([self.fieldtype, self.fieldname, self.length,
                    self.lengthfield])


class Field():
    type = 'Field'

    def __init__(self, fieldtype, name, limit=None):
        # limit field has been expanded to an options dict.

        self.fieldtype = fieldtype
        self.is_lengthfield = False

        if self.fieldtype == 'string':
            raise ValueError("The string type {!r} is an "
                             "array type ".format(name))

        if name in keyword.kwlist:
            raise ValueError("Fieldname {!r} is a python keyword and is not "
                             "accessible via the python API. ".format(name))
        self.fieldname = name
        self.limit = limit

    def __repr__(self):
        return str([self.fieldtype, self.fieldname])


class Counter(Processable):
    type = 'Counter'

    def __init__(self, path, counter):
        self.name = path
        self.block = counter

    def process(self, result):  # -> Dict
        result['Counters'].append(self)


class Paths(Processable):
    type = 'Paths'

    def __init__(self, pathset):
        self.paths = pathset

    def __repr__(self):
        return "%s(paths=%s)" % (
            self.__class__.__name__, self.paths
        )


class Coord(object):
    """ Coordinates of a syntactic element. Consists of:
            - File name
            - Line number
            - (optional) column number, for the Lexer
    """
    __slots__ = ('file', 'line', 'column', '__weakref__')

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
class VPPAPIParser(object):
    tokens = VPPAPILexer.tokens

    def __init__(self, filename, logger, revision=None):
        self.filename = filename
        self.logger = logger
        self.fields = []
        self.revision = revision

    def _parse_error(self, msg, coord):
        raise ParseError("%s: %s" % (coord, msg))

    def _parse_warning(self, msg, coord):
        if self.logger:
            self.logger.warning("%s: %s" % (coord, msg))

    def _coord(self, lineno, column=None):
        return Coord(
            file=self.filename,
            line=lineno, column=column)

    def _token_coord(self, p, token_idx):
        """ Returns the coordinates for the YaccProduction object 'p' indexed
            with 'token_idx'. The coordinate includes the 'lineno' and
            'column'. Both follow the lex semantic, starting from 1.
        """
        last_cr = p.lexer.lexdata.rfind('\n', 0, p.lexpos(token_idx))
        if last_cr < 0:
            last_cr = -1
        column = (p.lexpos(token_idx) - (last_cr))
        return self._coord(p.lineno(token_idx), column)

    def p_slist(self, p):
        '''slist : stmt
                 | slist stmt'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_stmt(self, p):
        '''stmt : define
                | typedef
                | option
                | import
                | enum
                | enumflag
                | union
                | service
                | paths
                | counters'''
        p[0] = p[1]

    def p_import(self, p):
        '''import : IMPORT STRING_LITERAL ';' '''
        p[0] = Import(p[2], revision=self.revision)

    def p_path_elements(self, p):
        '''path_elements : path_element
                            | path_elements path_element'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            if type(p[1]) is dict:
                p[0] = [p[1], p[2]]
            else:
                p[0] = p[1] + [p[2]]

    def p_path_element(self, p):
        '''path_element : STRING_LITERAL STRING_LITERAL ';' '''
        p[0] = {'path': p[1], 'counter': p[2]}

    def p_paths(self, p):
        '''paths : PATHS '{' path_elements '}' ';' '''
        p[0] = Paths(p[3])

    def p_counters(self, p):
        '''counters : COUNTERS ID '{' counter_elements '}' ';' '''
        p[0] = Counter(p[2], p[4])

    def p_counter_elements(self, p):
        '''counter_elements : counter_element
                            | counter_elements counter_element'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            if type(p[1]) is dict:
                p[0] = [p[1], p[2]]
            else:
                p[0] = p[1] + [p[2]]

    def p_counter_element(self, p):
        '''counter_element : ID '{' counter_statements '}' ';' '''
        p[0] = {**{'name': p[1]}, **p[3]}

    def p_counter_statements(self, p):
        '''counter_statements : counter_statement
                        | counter_statements counter_statement'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = {**p[1], **p[2]}

    def p_counter_statement(self, p):
        '''counter_statement : SEVERITY ID ';'
                             | UNITS STRING_LITERAL ';'
                             | DESCRIPTION STRING_LITERAL ';'
                             | TYPE ID ';' '''
        p[0] = {p[1]: p[2]}

    def p_service(self, p):
        '''service : SERVICE '{' service_statements '}' ';' '''
        p[0] = p[3]

    def p_service_statements(self, p):
        '''service_statements : service_statement
                        | service_statements service_statement'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_service_statement(self, p):
        '''service_statement : RPC ID RETURNS NULL ';'
                             | RPC ID RETURNS ID ';'
                             | RPC ID RETURNS STREAM ID ';'
                             | RPC ID RETURNS ID EVENTS event_list ';' '''
        if p[2] == p[4]:
            # Verify that caller and reply differ
            self._parse_error(
                'Reply ID ({}) should not be equal to Caller ID'.format(p[2]),
                self._token_coord(p, 1))
        if len(p) == 8:
            p[0] = Service(p[2], p[4], p[6])
        elif len(p) == 7:
            p[0] = Service(p[2], p[5], stream=True)
        else:
            p[0] = Service(p[2], p[4])

    def p_service_statement2(self, p):
        '''service_statement : RPC ID RETURNS ID STREAM ID ';' '''
        p[0] = Service(p[2], p[4], stream_message=p[6], stream=True)

    def p_event_list(self, p):
        '''event_list : events
                      | event_list events '''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_event(self, p):
        '''events : ID
                  | ID ',' '''
        p[0] = p[1]

    def p_enum(self, p):
        '''enum : ENUM ID '{' enum_statements '}' ';' '''
        p[0] = Enum(p[2], p[4])

    def p_enum_type(self, p):
        ''' enum : ENUM ID ':' enum_size '{' enum_statements '}' ';' '''
        if len(p) == 9:
            p[0] = Enum(p[2], p[6], enumtype=p[4])
        else:
            p[0] = Enum(p[2], p[4])

    def p_enumflag(self, p):
        '''enumflag : ENUMFLAG ID '{' enum_statements '}' ';' '''
        p[0] = EnumFlag(p[2], p[4])

    def p_enumflag_type(self, p):
        ''' enumflag : ENUMFLAG ID ':' enum_size '{' enum_statements '}' ';' '''  # noqa : E502
        if len(p) == 9:
            p[0] = EnumFlag(p[2], p[6], enumtype=p[4])
        else:
            p[0] = EnumFlag(p[2], p[4])

    def p_enum_size(self, p):
        ''' enum_size : U8
                      | U16
                      | U32 '''
        p[0] = p[1]

    def p_define(self, p):
        '''define : DEFINE ID '{' block_statements_opt '}' ';' '''
        self.fields = []
        p[0] = Define(p[2], [], p[4])

    def p_define_flist(self, p):
        '''define : flist DEFINE ID '{' block_statements_opt '}' ';' '''
        # Legacy typedef
        if 'typeonly' in p[1]:
            self._parse_error('legacy typedef. use typedef: {} {}[{}];'
                              .format(p[1], p[2], p[4]),
                              self._token_coord(p, 1))
        else:
            p[0] = Define(p[3], p[1], p[5])

    def p_flist(self, p):
        '''flist : flag
                 | flist flag'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_flag(self, p):
        '''flag : MANUAL_PRINT
                | MANUAL_ENDIAN
                | DONT_TRACE
                | TYPEONLY
                | AUTOREPLY'''
        if len(p) == 1:
            return
        p[0] = p[1]

    def p_typedef(self, p):
        '''typedef : TYPEDEF ID '{' block_statements_opt '}' ';' '''
        p[0] = Typedef(p[2], [], p[4])

    def p_typedef_flist(self, p):
        '''typedef : flist TYPEDEF ID '{' block_statements_opt '}' ';' '''
        p[0] = Typedef(p[3], p[1], p[5])

    def p_typedef_alias(self, p):
        '''typedef : TYPEDEF declaration '''
        p[0] = Using(p[2].fieldname, [], p[2])

    def p_typedef_alias_flist(self, p):
        '''typedef : flist TYPEDEF declaration '''
        p[0] = Using(p[3].fieldname, p[1], p[3])

    def p_block_statements_opt(self, p):
        '''block_statements_opt : block_statements '''
        p[0] = p[1]

    def p_block_statements(self, p):
        '''block_statements : block_statement
                            | block_statements block_statement'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_block_statement(self, p):
        '''block_statement : declaration
                           | option '''
        p[0] = p[1]

    def p_enum_statements(self, p):
        '''enum_statements : enum_statement
                           | enum_statements enum_statement'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = p[1] + [p[2]]

    def p_enum_statement(self, p):
        '''enum_statement : ID '=' NUM ','
                          | ID ','
                          | ID '[' field_options ']' ','
                          | ID '=' NUM '[' field_options ']' ',' '''
        if len(p) == 3:
            p[0] = {'id': p[1]}
        elif len(p) == 5:
            p[0] = {'id': p[1], 'value': p[3]}
        elif len(p) == 6:
            p[0] = {'id': p[1], 'option': p[3]}
        elif len(p) == 8:
            p[0] = {'id': p[1], 'value': p[3], 'option': p[5]}
        else:
            self._parse_error('ERROR', self._token_coord(p, 1))

    def p_field_options(self, p):
        '''field_options : field_option
                           | field_options field_option'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = {**p[1], **p[2]}

    def p_field_option(self, p):
        '''field_option : ID
                        | ID '=' assignee ','
                        | ID '=' assignee

        '''
        if len(p) == 2:
            p[0] = {p[1]: None}
        else:
            p[0] = {p[1]: p[3]}

    def p_variable_name(self, p):
        '''variable_name : ID
                         | TYPE
                         | SEVERITY
                         | DESCRIPTION
                         | COUNTERS
                         | PATHS
        '''
        p[0] = p[1]

    def p_declaration(self, p):
        '''declaration : type_specifier variable_name ';'
                       | type_specifier variable_name '[' field_options ']' ';'
        '''
        if len(p) == 7:
            p[0] = Field(p[1], p[2], p[4])
        elif len(p) == 4:
            p[0] = Field(p[1], p[2])
        else:
            self._parse_error('ERROR', self._token_coord(p, 1))
        self.fields.append(p[2])

    def p_declaration_array_vla(self, p):
        '''declaration : type_specifier variable_name '[' ']' ';' '''
        p[0] = Array(p[1], p[2], 0, modern_vla=True)

    def p_declaration_array(self, p):
        '''declaration : type_specifier variable_name '[' NUM ']' ';'
                       | type_specifier variable_name '[' ID ']' ';' '''

        if len(p) != 7:
            return self._parse_error(
                'array: %s' % p.value,
                self._coord(lineno=p.lineno))

        # Make this error later
        if type(p[4]) is int and p[4] == 0:
            # XXX: Line number is wrong
            self._parse_warning('Old Style VLA: {} {}[{}];'
                                .format(p[1], p[2], p[4]),
                                self._token_coord(p, 1))

        if type(p[4]) is str and p[4] not in self.fields:
            # Verify that length field exists
            self._parse_error('Missing length field: {} {}[{}];'
                              .format(p[1], p[2], p[4]),
                              self._token_coord(p, 1))
        p[0] = Array(p[1], p[2], p[4])

    def p_option(self, p):
        '''option : OPTION ID '=' assignee ';'
                  | OPTION ID ';' '''
        if len(p) == 4:
            p[0] = Option(p[2])
        else:
            p[0] = Option(p[2], p[4])

    def p_assignee(self, p):
        '''assignee : NUM
                    | TRUE
                    | FALSE
                    | STRING_LITERAL '''
        p[0] = p[1]

    def p_type_specifier(self, p):
        '''type_specifier : U8
                          | U16
                          | U32
                          | U64
                          | I8
                          | I16
                          | I32
                          | I64
                          | F64
                          | BOOL
                          | STRING'''
        p[0] = p[1]

    # Do a second pass later to verify that user defined types are defined
    def p_typedef_specifier(self, p):
        '''type_specifier : ID '''
        if p[1] not in global_types:
            self._parse_error('Undefined type: {}'.format(p[1]),
                              self._token_coord(p, 1))
        p[0] = p[1]

    def p_union(self, p):
        '''union : UNION ID '{' block_statements_opt '}' ';' '''
        p[0] = Union(p[2], [], p[4])

    def p_union_flist(self, p):
        '''union : flist UNION ID '{' block_statements_opt '}' ';' '''
        p[0] = Union(p[3], p[1], p[5])

    # Error rule for syntax errors
    def p_error(self, p):
        if p:
            self._parse_error(
                'before: %s' % p.value,
                self._coord(lineno=p.lineno))
        else:
            self._parse_error('At end of input', self.filename)


class VPPAPI():

    def __init__(self, debug=False, filename='', logger=None, revision=None):
        self.lexer = lex.lex(module=VPPAPILexer(filename), debug=debug)
        self.parser = yacc.yacc(module=VPPAPIParser(filename, logger,
                                                    revision=revision),
                                write_tables=False, debug=debug)
        self.logger = logger
        self.revision = revision
        self.filename = filename

    def parse_string(self, code, debug=0, lineno=1):
        self.lexer.lineno = lineno
        return self.parser.parse(code, lexer=self.lexer, debug=debug)

    def parse_fd(self, fd, debug=0):
        data = fd.read()
        return self.parse_string(data, debug=debug)

    def parse_filename(self, filename, debug=0):
        if self.revision:
            git_show = 'git show {}:{}'.format(self.revision, filename)
            proc = Popen(git_show.split(), stdout=PIPE, encoding='utf-8')
            try:
                data, errs = proc.communicate()
                if proc.returncode != 0:
                    print('File not found: {}:{}'
                          .format(self.revision, filename), file=sys.stderr)
                    sys.exit(2)
                return self.parse_string(data, debug=debug)
            except Exception:
                sys.exit(3)
        else:
            try:
                with open(filename, encoding='utf-8') as fd:
                    return self.parse_fd(fd, None)
            except FileNotFoundError:
                print('File not found: {}'.format(filename), file=sys.stderr)
                sys.exit(2)

    def process(self, objs):
        s = {}
        s['Option'] = {}
        s['Define'] = []
        s['Service'] = []
        s['types'] = []
        s['Import'] = []
        s['Counters'] = []
        s['Paths'] = []
        crc = 0
        for o in objs:
            try:
                crc = binascii.crc32(o.crc, crc) & 0xffffffff
            except AttributeError:
                pass

            if type(o) is list:
                for o2 in o:
                    if isinstance(o2, Service):
                        o2.process(s)
            else:
                o.process(s)

        msgs = {d.name: d for d in s['Define']}
        svcs = {s.caller: s for s in s['Service']}
        replies = {s.reply: s for s in s['Service']}
        seen_services = {}

        s['file_crc'] = crc

        for service in svcs:
            if service not in msgs:
                raise ValueError(
                    'Service definition refers to unknown message'
                    ' definition: {}'.format(service))
            if svcs[service].reply != 'null' and \
               svcs[service].reply not in msgs:
                raise ValueError('Service definition refers to unknown message'
                                 ' definition in reply: {}'
                                 .format(svcs[service].reply))
            if service in replies:
                raise ValueError('Service definition refers to message'
                                 ' marked as reply: {}'.format(service))
            for event in svcs[service].events:
                if event not in msgs:
                    raise ValueError('Service definition refers to unknown '
                                     'event: {} in message: {}'
                                     .format(event, service))
                seen_services[event] = True

        # Create services implicitly
        for d in msgs:
            if d in seen_services:
                continue
            if msgs[d].singular is True:
                continue
            if d.endswith('_reply'):
                if d[:-6] in svcs:
                    continue
                if d[:-6] not in msgs:
                    raise ValueError('{} missing calling message'
                                     .format(d))
                continue
            if d.endswith('_dump'):
                if d in svcs:
                    continue
                if d[:-5]+'_details' in msgs:
                    s['Service'].append(Service(d, d[:-5]+'_details',
                                                stream=True))
                else:
                    raise ValueError('{} missing details message'
                                     .format(d))
                continue

            if d.endswith('_details'):
                if d[:-8]+'_get' in msgs:
                    if d[:-8]+'_get' in svcs:
                        continue
                    raise ValueError('{} should be in a stream service'
                                     .format(d[:-8]+'_get'))
                if d[:-8]+'_dump' in msgs:
                    continue
                raise ValueError('{} missing dump or get message'
                                 .format(d))

            if d in svcs:
                continue
            if d+'_reply' in msgs:
                s['Service'].append(Service(d, d+'_reply'))
            else:
                raise ValueError(
                    '{} missing reply message ({}) or service definition'
                    .format(d, d+'_reply'))

        return s

    def process_imports(self, objs, in_import, result):  # -> List
        for o in objs:
            # Only allow the following object types from imported file
            if in_import and not isinstance(o, (Enum, Import, Typedef,
                                                Union, Using)):
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
        o.block.insert(0, Field('u16', '_vl_msg_id'))
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
        if b.fieldtype.startswith('vl_api_'):
            # Recursively
            t = global_types[b.fieldtype]
            try:
                crc = binascii.crc32(t.crc, crc) & 0xffffffff
                crc = foldup_blocks(t.block, crc)
            except AttributeError:
                pass
    return crc


# keep the CRCs of the existing types of messages compatible with the
# old "erroneous" way of calculating the CRC. For that - make a pointed
# adjustment of the CRC function.
# This is the purpose of the first element of the per-message dictionary.
# The second element is there to avoid weakening the duplicate-detecting
# properties of crc32. This way, if the new way of calculating the CRC
# happens to collide with the old (buggy) way - we will still get
# a different result and fail the comparison.

fixup_crc_dict = {
        "abf_policy_add_del": {0xc6131197: 0xee66f93e},
        "abf_policy_details": {0xb7487fa4: 0x6769e504},
        "acl_add_replace": {0xee5c2f18: 0x1cabdeab},
        "acl_details": {0x95babae0: 0x7a97f21c},
        "macip_acl_add": {0xce6fbad0: 0xd648fd0a},
        "macip_acl_add_replace": {0x2a461dd4: 0xe34402a7},
        "macip_acl_details": {0x27135b59: 0x57c7482f},
        "dhcp_proxy_config": {0x4058a689: 0x6767230e},
        "dhcp_client_config": {0x1af013ea: 0x959b80a3},
        "dhcp_compl_event": {0x554a44e5: 0xe908fd1d},
        "dhcp_client_details": {0x3c5cd28a: 0xacd82f5a},
        "dhcp_proxy_details": {0xdcbaf540: 0xce16f044},
        "dhcp6_send_client_message": {0xf8222476: 0xf6f14ef0},
        "dhcp6_pd_send_client_message": {0x3739fd8d: 0x64badb8},
        "dhcp6_reply_event": {0x85b7b17e: 0x9f3af9e5},
        "dhcp6_pd_reply_event": {0x5e878029: 0xcb3e462b},
        "ip6_add_del_address_using_prefix": {0x3982f30a: 0x9b3d11e0},
        "gbp_bridge_domain_add": {0x918e8c01: 0x8454bfdf},
        "gbp_bridge_domain_details": {0x51d51be9: 0x2acd15f9},
        "gbp_route_domain_add": {0x204c79e1: 0x2d0afe38},
        "gbp_route_domain_details": {0xa78bfbca: 0x8ab11375},
        "gbp_endpoint_add": {0x7b3af7de: 0x9ce16d5a},
        "gbp_endpoint_details": {0x8dd8fbd3: 0x8aecb60},
        "gbp_endpoint_group_add": {0x301ddf15: 0x8e0f4054},
        "gbp_endpoint_group_details": {0xab71d723: 0x8f38292c},
        "gbp_subnet_add_del": {0xa8803c80: 0x888aca35},
        "gbp_subnet_details": {0xcbc5ca18: 0x4ed84156},
        "gbp_contract_add_del": {0xaa8d652d: 0x553e275b},
        "gbp_contract_details": {0x65dec325: 0x2a18db6e},
        "gbp_ext_itf_add_del": {0x7606d0e1: 0x12ed5700},
        "gbp_ext_itf_details": {0x519c3d3c: 0x408a45c0},
        "gtpu_add_del_tunnel": {0xca983a2b: 0x9a9c0426},
        "gtpu_tunnel_update_tteid": {0x79f33816: 0x8a2db108},
        "gtpu_tunnel_details": {0x27f434ae: 0x4535cf95},
        "igmp_listen": {0x19a49f1e: 0x3f93a51a},
        "igmp_details": {0x38f09929: 0x52f12a89},
        "igmp_event": {0x85fe93ec: 0xd7696eaf},
        "igmp_group_prefix_set": {0x5b14a5ce: 0xd4f20ac5},
        "igmp_group_prefix_details": {0x259ccd81: 0xc3b3c526},
        "ikev2_set_responder": {0xb9aa4d4e: 0xf0d3dc80},
        "vxlan_gpe_ioam_export_enable_disable": {0xd4c76d3a: 0xe4d4ebfa},
        "ioam_export_ip6_enable_disable": {0xd4c76d3a: 0xe4d4ebfa},
        "vxlan_gpe_ioam_vni_enable": {0xfbb5fb1: 0x997161fb},
        "vxlan_gpe_ioam_vni_disable": {0xfbb5fb1: 0x997161fb},
        "vxlan_gpe_ioam_transit_enable": {0x3d3ec657: 0x553f5b7b},
        "vxlan_gpe_ioam_transit_disable": {0x3d3ec657: 0x553f5b7b},
        "udp_ping_add_del": {0xfa2628fc: 0xc692b188},
        "l3xc_update": {0xe96aabdf: 0x787b1d3},
        "l3xc_details": {0xbc5bf852: 0xd4f69627},
        "sw_interface_lacp_details": {0xd9a83d2f: 0x745ae0ba},
        "lb_conf": {0x56cd3261: 0x22ddb739},
        "lb_add_del_vip": {0x6fa569c7: 0xd15b7ddc},
        "lb_add_del_as": {0x35d72500: 0x78628987},
        "lb_vip_dump": {0x56110cb7: 0xc7bcb124},
        "lb_vip_details": {0x1329ec9b: 0x8f39bed},
        "lb_as_details": {0x8d24c29e: 0x9c39f60e},
        "mactime_add_del_range": {0xcb56e877: 0x101858ef},
        "mactime_details": {0xda25b13a: 0x44921c06},
        "map_add_domain": {0x249f195c: 0x7a5a18c9},
        "map_domain_details": {0x796edb50: 0xfc1859dd},
        "map_param_add_del_pre_resolve": {0xdae5af03: 0x17008c66},
        "map_param_get_reply": {0x26272c90: 0x28092156},
        "memif_details": {0xda34feb9: 0xd0382c4c},
        "dslite_add_del_pool_addr_range": {0xde2a5b02: 0xc448457a},
        "dslite_set_aftr_addr": {0x78b50fdf: 0x1e955f8d},
        "dslite_get_aftr_addr_reply": {0x8e23608e: 0x38e30db1},
        "dslite_set_b4_addr": {0x78b50fdf: 0x1e955f8d},
        "dslite_get_b4_addr_reply": {0x8e23608e: 0x38e30db1},
        "nat44_add_del_address_range": {0x6f2b8055: 0xd4c7568c},
        "nat44_address_details": {0xd1beac1: 0x45410ac4},
        "nat44_add_del_static_mapping": {0x5ae5f03e: 0xe165e83b},
        "nat44_static_mapping_details": {0x6cb40b2: 0x1a433ef7},
        "nat44_add_del_identity_mapping": {0x2faaa22: 0x8e12743f},
        "nat44_identity_mapping_details": {0x2a52a030: 0x36d21351},
        "nat44_add_del_interface_addr": {0x4aed50c0: 0xfc835325},
        "nat44_interface_addr_details": {0xe4aca9ca: 0x3e687514},
        "nat44_user_session_details": {0x2cf6e16d: 0x1965fd69},
        "nat44_add_del_lb_static_mapping": {0x4f68ee9d: 0x53b24611},
        "nat44_lb_static_mapping_add_del_local": {0x7ca47547: 0x2910a151},
        "nat44_lb_static_mapping_details": {0xed5ce876: 0x2267b9e8},
        "nat44_del_session": {0x15a5bf8c: 0x4c49c387},
        "nat_det_add_del_map": {0x1150a190: 0x112fde05},
        "nat_det_map_details": {0xad91dc83: 0x88000ee1},
        "nat_det_close_session_out": {0xf6b259d1: 0xc1b6cbfb},
        "nat_det_close_session_in": {0x3c68e073: 0xa10ef64},
        "nat64_add_del_pool_addr_range": {0xa3b944e3: 0x21234ef3},
        "nat64_add_del_static_bib": {0x1c404de5: 0x90fae58a},
        "nat64_bib_details": {0x43bc3ddf: 0x62c8541d},
        "nat64_st_details": {0xdd3361ed: 0xc770d620},
        "nat66_add_del_static_mapping": {0x3ed88f71: 0xfb64e50b},
        "nat66_static_mapping_details": {0xdf39654b: 0x5c568448},
        "nsh_add_del_map": {0xa0f42b0: 0x898d857d},
        "nsh_map_details": {0x2fefcf49: 0xb34ac8a1},
        "nsim_cross_connect_enable_disable": {0x9c3ead86: 0x16f70bdf},
        "pppoe_add_del_session": {0xf6fd759e: 0x46ace853},
        "pppoe_session_details": {0x4b8e8a4a: 0x332bc742},
        "stn_add_del_rule": {0x224c6edd: 0x53f751e6},
        "stn_rules_details": {0xa51935a6: 0xb0f6606c},
        "svs_route_add_del": {0xe49bc63c: 0xd39e31fc},
        "svs_details": {0x6282cd55: 0xb8523d64},
        "vmxnet3_details": {0x6a1a5498: 0x829ba055},
        "vrrp_vr_add_del": {0xc5cf15aa: 0x6dc4b881},
        "vrrp_vr_details": {0x46edcebd: 0x412fa71},
        "vrrp_vr_set_peers": {0x20bec71f: 0xbaa2e52b},
        "vrrp_vr_peer_details": {0x3d99c108: 0xabd9145e},
        "vrrp_vr_track_if_add_del": {0xd67df299: 0x337f4ba4},
        "vrrp_vr_track_if_details": {0x73c36f81: 0x99bcca9c},
        "proxy_arp_add_del": {0x1823c3e7: 0x85486cbd},
        "proxy_arp_details": {0x5b948673: 0x9228c150},
        "bfd_udp_get_echo_source_reply": {0xe3d736a1: 0x1e00cfce},
        "bfd_udp_add": {0x939cd26a: 0x7a6d1185},
        "bfd_udp_mod": {0x913df085: 0x783a3ff6},
        "bfd_udp_del": {0xdcb13a89: 0x8096514d},
        "bfd_udp_session_details": {0x9fb2f2d: 0x60653c02},
        "bfd_udp_session_set_flags": {0x4b4bdfd: 0xcf313851},
        "bfd_udp_auth_activate": {0x21fd1bdb: 0x493ee0ec},
        "bfd_udp_auth_deactivate": {0x9a05e2e0: 0x99978c32},
        "bier_route_add_del": {0xfd02f3ea: 0xf29edca0},
        "bier_route_details": {0x4008caee: 0x39ee6a56},
        "bier_disp_entry_add_del": {0x9eb80cb4: 0x648323eb},
        "bier_disp_entry_details": {0x84c218f1: 0xe5b039a9},
        "bond_create": {0xf1dbd4ff: 0x48883c7e},
        "bond_enslave": {0xe7d14948: 0x76ecfa7},
        "sw_interface_bond_details": {0xbb7c929b: 0xf5ef2106},
        "pipe_create_reply": {0xb7ce310c: 0xd4c2c2b3},
        "pipe_details": {0xc52b799d: 0x43ac107a},
        "tap_create_v2": {0x2d0d6570: 0x445835fd},
        "sw_interface_tap_v2_details": {0x1e2b2a47: 0xe53c16de},
        "sw_interface_vhost_user_details": {0xcee1e53: 0x98530df1},
        "virtio_pci_create": {0x1944f8db: 0xa9f1370c},
        "sw_interface_virtio_pci_details": {0x6ca9c167: 0x16187f3a},
        "p2p_ethernet_add": {0x36a1a6dc: 0xeeb8e717},
        "p2p_ethernet_del": {0x62f81c8c: 0xb62c386},
        "geneve_add_del_tunnel": {0x99445831: 0x976693b5},
        "geneve_tunnel_details": {0x6b16eb24: 0xe27e2748},
        "gre_tunnel_add_del": {0xa27d7f17: 0x6efc9c22},
        "gre_tunnel_details": {0x24435433: 0x3bfbf1},
        "sw_interface_set_flags": {0xf5aec1b8: 0x6a2b491a},
        "sw_interface_event": {0x2d3d95a7: 0xf709f78d},
        "sw_interface_details": {0x6c221fc7: 0x17b69fa2},
        "sw_interface_add_del_address": {0x5463d73b: 0x5803d5c4},
        "sw_interface_set_unnumbered": {0x154a6439: 0x938ef33b},
        "sw_interface_set_mac_address": {0xc536e7eb: 0x6aca746a},
        "sw_interface_set_rx_mode": {0xb04d1cfe: 0x780f5cee},
        "sw_interface_rx_placement_details": {0x9e44a7ce: 0xf6d7d024},
        "create_subif": {0x790ca755: 0xcb371063},
        "ip_neighbor_add_del": {0x607c257: 0x105518b6},
        "ip_neighbor_dump": {0xd817a484: 0xcd831298},
        "ip_neighbor_details": {0xe29d79f0: 0x870e80b9},
        "want_ip_neighbor_events": {0x73e70a86: 0x1a312870},
        "ip_neighbor_event": {0xbdb092b2: 0x83933131},
        "ip_route_add_del": {0xb8ecfe0d: 0xc1ff832d},
        "ip_route_details": {0xbda8f315: 0xd1ffaae1},
        "ip_route_lookup": {0x710d6471: 0xe2986185},
        "ip_route_lookup_reply": {0x5d8febcb: 0xae99de8e},
        "ip_mroute_add_del": {0x85d762f3: 0xf6627d17},
        "ip_mroute_details": {0x99341a45: 0xc1cb4b44},
        "ip_address_details": {0xee29b797: 0xb1199745},
        "ip_unnumbered_details": {0xcc59bd42: 0xaa12a483},
        "mfib_signal_details": {0x6f4a4cfb: 0x64398a9a},
        "ip_punt_redirect": {0x6580f635: 0xa9a5592c},
        "ip_punt_redirect_details": {0x2cef63e7: 0x3924f5d3},
        "ip_container_proxy_add_del": {0x7df1dff1: 0x91189f40},
        "ip_container_proxy_details": {0xa8085523: 0xee460e8},
        "ip_source_and_port_range_check_add_del": {0x92a067e3: 0x8bfc76f2},
        "sw_interface_ip6_set_link_local_address": {0x1c10f15f: 0x2931d9fa},
        "ip_reassembly_enable_disable": {0xeb77968d: 0x885c85a6},
        "set_punt": {0xaa83d523: 0x83799618},
        "punt_socket_register": {0x95268cbf: 0xc8cd10fa},
        "punt_socket_details": {0xde575080: 0x1de0ce75},
        "punt_socket_deregister": {0x98fc9102: 0x98a444f4},
        "sw_interface_ip6nd_ra_prefix": {0x82cc1b28: 0xe098785f},
        "ip6nd_proxy_add_del": {0xc2e4a686: 0x3fdf6659},
        "ip6nd_proxy_details": {0x30b9ff4a: 0xd35be8ff},
        "ip6_ra_event": {0x364c1c5: 0x47e8cfbe},
        "set_ipfix_exporter": {0x5530c8a0: 0x69284e07},
        "ipfix_exporter_details": {0xdedbfe4: 0x11e07413},
        "ipip_add_tunnel": {0x2ac399f5: 0xa9decfcd},
        "ipip_6rd_add_tunnel": {0xb9ec1863: 0x56e93cc0},
        "ipip_tunnel_details": {0xd31cb34e: 0x53236d75},
        "ipsec_spd_entry_add_del": {0x338b7411: 0x9f384b8d},
        "ipsec_spd_details": {0x5813d7a2: 0xf2222790},
        "ipsec_sad_entry_add_del": {0xab64b5c6: 0xb8def364},
        "ipsec_tunnel_protect_update": {0x30d5f133: 0x143f155d},
        "ipsec_tunnel_protect_del": {0xcd239930: 0xddd2ba36},
        "ipsec_tunnel_protect_details": {0x21663a50: 0xac6c823b},
        "ipsec_tunnel_if_add_del": {0x20e353fa: 0x2b135e68},
        "ipsec_sa_details": {0x345d14a7: 0xb30c7f41},
        "l2_xconnect_details": {0x472b6b67: 0xc8aa6b37},
        "l2_fib_table_details": {0xa44ef6b8: 0xe8d2fc72},
        "l2fib_add_del": {0xeddda487: 0xf29d796c},
        "l2_macs_event": {0x44b8fd64: 0x2eadfc8b},
        "bridge_domain_details": {0xfa506fd: 0x979f549d},
        "l2_interface_pbb_tag_rewrite": {0x38e802a8: 0x612efa5a},
        "l2_patch_add_del": {0xa1f6a6f3: 0x522f3445},
        "sw_interface_set_l2_xconnect": {0x4fa28a85: 0x1aaa2dbb},
        "sw_interface_set_l2_bridge": {0xd0678b13: 0x2e483cd0},
        "bd_ip_mac_add_del": {0x257c869: 0x5f2b84e2},
        "bd_ip_mac_details": {0x545af86a: 0xa52f8044},
        "l2_arp_term_event": {0x6963e07a: 0x85ff71ea},
        "l2tpv3_create_tunnel": {0x15bed0c2: 0x596892cb},
        "sw_if_l2tpv3_tunnel_details": {0x50b88993: 0x1dab5c7e},
        "lisp_add_del_local_eid": {0x4e5a83a2: 0x21f573bd},
        "lisp_add_del_map_server": {0xce19e32d: 0x6598ea7c},
        "lisp_add_del_map_resolver": {0xce19e32d: 0x6598ea7c},
        "lisp_use_petr": {0xd87dbad9: 0x9e141831},
        "show_lisp_use_petr_reply": {0x22b9a4b0: 0xdcad8a81},
        "lisp_add_del_remote_mapping": {0x6d5c789e: 0xfae8ed77},
        "lisp_add_del_adjacency": {0x2ce0e6f6: 0xcf5edb61},
        "lisp_locator_details": {0x2c620ffe: 0xc0c4c2a7},
        "lisp_eid_table_details": {0x1c29f792: 0x4bc32e3a},
        "lisp_eid_table_dump": {0x629468b5: 0xb959b73b},
        "lisp_adjacencies_get_reply": {0x807257bf: 0x3f97bcdd},
        "lisp_map_resolver_details": {0x3e78fc57: 0x82a09deb},
        "lisp_map_server_details": {0x3e78fc57: 0x82a09deb},
        "one_add_del_local_eid": {0x4e5a83a2: 0x21f573bd},
        "one_add_del_map_server": {0xce19e32d: 0x6598ea7c},
        "one_add_del_map_resolver": {0xce19e32d: 0x6598ea7c},
        "one_use_petr": {0xd87dbad9: 0x9e141831},
        "show_one_use_petr_reply": {0x84a03528: 0x10e744a6},
        "one_add_del_remote_mapping": {0x6d5c789e: 0xfae8ed77},
        "one_add_del_l2_arp_entry": {0x1aa5e8b3: 0x33209078},
        "one_l2_arp_entries_get_reply": {0xb0dd200f: 0xb0a47bbe},
        "one_add_del_ndp_entry": {0xf8a287c: 0xd1629a2f},
        "one_ndp_entries_get_reply": {0x70719b1a: 0xbd34161},
        "one_add_del_adjacency": {0x9e830312: 0xe48e7afe},
        "one_locator_details": {0x2c620ffe: 0xc0c4c2a7},
        "one_eid_table_details": {0x1c29f792: 0x4bc32e3a},
        "one_eid_table_dump": {0xbd190269: 0x95151038},
        "one_adjacencies_get_reply": {0x85bab89: 0xa8ed89a5},
        "one_map_resolver_details": {0x3e78fc57: 0x82a09deb},
        "one_map_server_details": {0x3e78fc57: 0x82a09deb},
        "one_stats_details": {0x2eb74678: 0xff6ef238},
        "gpe_add_del_fwd_entry": {0xf0847644: 0xde6df50f},
        "gpe_fwd_entries_get_reply": {0xc4844876: 0xf9f53f1b},
        "gpe_fwd_entry_path_details": {0x483df51a: 0xee80b19a},
        "gpe_add_del_native_fwd_rpath": {0x43fc8b54: 0x812da2f2},
        "gpe_native_fwd_rpaths_get_reply": {0x7a1ca5a2: 0x79d54eb9},
        "sw_interface_set_lldp": {0x57afbcd4: 0xd646ae0f},
        "mpls_ip_bind_unbind": {0xc7533b32: 0x48249a27},
        "mpls_tunnel_add_del": {0x44350ac1: 0xe57ce61d},
        "mpls_tunnel_details": {0x57118ae3: 0xf3c0928e},
        "mpls_route_add_del": {0x8e1d1e07: 0x343cff54},
        "mpls_route_details": {0x9b5043dc: 0xd0ac384c},
        "policer_add_del": {0x2b31dd38: 0xcb948f6e},
        "policer_details": {0x72d0e248: 0xa43f781a},
        "qos_store_enable_disable": {0xf3abcc8b: 0x3507235e},
        "qos_store_details": {0x3ee0aad7: 0x38a6d48},
        "qos_record_enable_disable": {0x2f1a4a38: 0x25b33f88},
        "qos_record_details": {0xa425d4d3: 0x4956ccdd},
        "session_rule_add_del": {0xe4895422: 0xe31f9443},
        "session_rules_details": {0x28d71830: 0x304b91f0},
        "sw_interface_span_enable_disable": {0x23ddd96b: 0xacc8fea1},
        "sw_interface_span_details": {0x8a20e79f: 0x55643fc},
        "sr_mpls_steering_add_del": {0x64acff63: 0x7d1b0a0b},
        "sr_mpls_policy_assign_endpoint_color": {0xe7eb978: 0x5e1c5c13},
        "sr_localsid_add_del": {0x5a36c324: 0x26fa3309},
        "sr_policy_add": {0x44ac92e8: 0xec79ee6a},
        "sr_policy_mod": {0xb97bb56e: 0xe531a102},
        "sr_steering_add_del": {0xe46b0a0f: 0x3711dace},
        "sr_localsids_details": {0x2e9221b9: 0x6a6c0265},
        "sr_policies_details": {0xdb6ff2a1: 0x7ec2d93},
        "sr_steering_pol_details": {0xd41258c9: 0x1c1ee786},
        "syslog_set_sender": {0xb8011d0b: 0xbb641285},
        "syslog_get_sender_reply": {0x424cfa4e: 0xd3da60ac},
        "tcp_configure_src_addresses": {0x67eede0d: 0x4b02b946},
        "teib_entry_add_del": {0x8016cfd2: 0x5aa0a538},
        "teib_details": {0x981ee1a1: 0xe3b6a503},
        "udp_encap_add": {0xf74a60b1: 0x61d5fc48},
        "udp_encap_details": {0x8cfb9c76: 0x87c82821},
        "vxlan_gbp_tunnel_add_del": {0x6c743427: 0x8c819166},
        "vxlan_gbp_tunnel_details": {0x66e94a89: 0x1da24016},
        "vxlan_gpe_add_del_tunnel": {0xa645b2b0: 0x7c6da6ae},
        "vxlan_gpe_tunnel_details": {0x968fc8b: 0x57712346},
        "vxlan_add_del_tunnel": {0xc09dc80: 0xa35dc8f5},
        "vxlan_tunnel_details": {0xc3916cb1: 0xe782f70f},
        "vxlan_offload_rx": {0x9cc95087: 0x89a1564b},
        "log_details": {0x3d61cc0: 0x255827a1},
}


def foldup_crcs(s):
    for f in s:
        f.crc = foldup_blocks(f.block,
                              binascii.crc32(f.crc) & 0xffffffff)

        # fixup the CRCs to make the fix seamless
        if f.name in fixup_crc_dict:
            if f.crc in fixup_crc_dict.get(f.name):
                f.crc = fixup_crc_dict.get(f.name).get(f.crc)


#
# Main
#
def main():
    if sys.version_info < (3, 5,):
        log.exception('vppapigen requires a supported version of python. '
                      'Please use version 3.5 or greater. '
                      'Using %s', sys.version)
        return 1

    cliparser = argparse.ArgumentParser(description='VPP API generator')
    cliparser.add_argument('--pluginpath', default="")
    cliparser.add_argument('--includedir', action='append')
    cliparser.add_argument('--outputdir', action='store')
    cliparser.add_argument('--input')
    cliparser.add_argument('--output', nargs='?',
                           type=argparse.FileType('w', encoding='UTF-8'),
                           default=sys.stdout)

    cliparser.add_argument('output_module', nargs='?', default='C')
    cliparser.add_argument('--debug', action='store_true')
    cliparser.add_argument('--show-name', nargs=1)
    cliparser.add_argument('--git-revision',
                           help="Git revision to use for opening files")
    args = cliparser.parse_args()

    dirlist_add(args.includedir)
    if not args.debug:
        sys.excepthook = exception_handler

    # Filename
    if args.show_name:
        filename = args.show_name[0]
    elif args.input:
        filename = args.input
    else:
        filename = ''

    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
    else:
        logging.basicConfig()

    #
    # Generate representation
    #
    from importlib.machinery import SourceFileLoader

    # Default path
    pluginpath = ''
    if not args.pluginpath:
        cand = []
        cand.append(os.path.dirname(os.path.realpath(__file__)))
        cand.append(os.path.dirname(os.path.realpath(__file__)) +
                    '/../share/vpp/')
        for c in cand:
            c += '/'
            if os.path.isfile('{}vppapigen_{}.py'
                              .format(c, args.output_module.lower())):
                pluginpath = c
                break
    else:
        pluginpath = args.pluginpath + '/'
    if pluginpath == '':
        log.exception('Output plugin not found')
        return 1
    module_path = '{}vppapigen_{}.py'.format(pluginpath,
                                             args.output_module.lower())

    try:
        plugin = SourceFileLoader(args.output_module,
                                  module_path).load_module()
    except Exception as err:
        log.exception('Error importing output plugin: %s, %s',
                      module_path, err)
        return 1

    parser = VPPAPI(debug=args.debug, filename=filename, logger=log,
                    revision=args.git_revision)

    try:
        if not args.input:
            parsed_objects = parser.parse_fd(sys.stdin, log)
        else:
            parsed_objects = parser.parse_filename(args.input, log)
    except ParseError as e:
        print('Parse error: ', e, file=sys.stderr)
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
        s['imported'] = parser.process(imports)

    # Add msg_id field
    s['Define'] = add_msg_id(s['Define'])

    # Fold up CRCs
    foldup_crcs(s['Define'])

    #
    # Debug
    if args.debug:
        import pprint
        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        for t in s['Define']:
            pp.pprint([t.name, t.flags, t.block])
        for t in s['types']:
            pp.pprint([t.name, t.block])

    result = plugin.run(args, filename, s)
    if result:
        print(result, file=args.output)
    else:
        log.exception('Running plugin failed: %s %s', filename, result)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
