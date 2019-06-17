#!/usr/bin/env python3

import ply.lex as lex
import ply.yacc as yacc
import sys
import argparse
import keyword
import logging
import binascii
import os
import sys
from subprocess import Popen, PIPE

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
        t.lexer.skip(1)

    # Define a rule so we can track line numbers
    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    literals = ":{}[];=.,"

    # A string containing ignored characters (spaces and tabs)
    t_ignore = ' \t'


def crc_block_combine(block, crc):
    s = str(block).encode()
    return binascii.crc32(s, crc) & 0xffffffff


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


class Service():
    def __init__(self, caller, reply, events=None, stream_message=None, stream=False):
        self.caller = caller
        self.reply = reply
        self.stream = stream
        self.stream_message = stream_message
        self.events = [] if events is None else events


class Typedef():
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

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Using():
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
        self.crc = str(alias).encode()
        global_type_add(name, self)

    def __repr__(self):
        return self.name + str(self.alias)


class Union():
    def __init__(self, name, flags, block):
        self.type = 'Union'
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

    def __repr__(self):
        return str(self.block)


class Define():
    def __init__(self, name, flags, block):
        self.name = name
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

        block = [x for x in block if not x in remove]
        self.block = block
        self.vla = vla_is_last_check(name, block)
        self.crc = str(block).encode()

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Enum():
    def __init__(self, name, block, enumtype='u32'):
        self.name = name
        self.enumtype = enumtype
        self.vla = False

        count = 0
        for i, b in enumerate(block):
            if type(b) is list:
                count = b[1]
            else:
                count += 1
                block[i] = [b, count]

        self.block = block
        self.crc = str(block).encode()
        global_type_add(name, self)

    def __repr__(self):
        return self.name + str(self.block)


class Import():

    def __new__(cls, *args, **kwargs):
        if args[0] not in seen_imports:
            instance = super().__new__(cls)
            instance._initialized = False
            seen_imports[args[0]] = instance

        return seen_imports[args[0]]

    def __init__(self, filename, revision):
        if self._initialized:
            return
        else:
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


class Option():
    def __init__(self, option, value):
        self.type = 'Option'
        self.option = option
        self.value = value
        self.crc = str(option).encode()

    def __repr__(self):
        return str(self.option)

    def __getitem__(self, index):
        return self.option[index]


class Array():
    def __init__(self, fieldtype, name, length, modern_vla=False):
        self.type = 'Array'
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
    def __init__(self, fieldtype, name, limit=None):
        self.type = 'Field'
        self.fieldtype = fieldtype

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
                | union
                | service'''
        p[0] = p[1]

    def p_import(self, p):
        '''import : IMPORT STRING_LITERAL ';' '''
        p[0] = Import(p[2], revision=self.revision)

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
                          | ID ',' '''
        if len(p) == 5:
            p[0] = [p[1], p[3]]
        else:
            p[0] = p[1]

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

    def p_declaration(self, p):
        '''declaration : type_specifier ID ';'
                       | type_specifier ID '[' field_options ']' ';' '''
        if len(p) == 7:
            p[0] = Field(p[1], p[2], p[4])
        elif len(p) == 4:
            p[0] = Field(p[1], p[2])
        else:
            self._parse_error('ERROR', self._token_coord(p, 1))
        self.fields.append(p[2])

    def p_declaration_array_vla(self, p):
        '''declaration : type_specifier ID '[' ']' ';' '''
        p[0] = Array(p[1], p[2], 0, modern_vla=True)

    def p_declaration_array(self, p):
        '''declaration : type_specifier ID '[' NUM ']' ';'
                       | type_specifier ID '[' ID ']' ';' '''

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
        '''option : OPTION ID '=' assignee ';' '''
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


class VPPAPI(object):

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
            git_show = f'git show  {self.revision}:{filename}'
            with Popen(git_show.split(), stdout=PIPE, encoding='utf-8') as git:
                return self.parse_fd(git.stdout, None)
        else:
            try:
                with open(filename, encoding='utf-8') as fd:
                    return self.parse_fd(fd, None)
            except FileNotFoundError:
                print(f'File not found: {filename}', file=sys.stderr)
                sys.exit(2)

    def autoreply_block(self, name, parent):
        block = [Field('u32', 'context'),
                 Field('i32', 'retval')]
        # inherhit the parent's options
        for k,v in parent.options.items():
            block.append(Option(k, v))
        return Define(name + '_reply', [], block)

    def process(self, objs):
        s = {}
        s['Option'] = {}
        s['Define'] = []
        s['Service'] = []
        s['types'] = []
        s['Import'] = []
        crc = 0
        for o in objs:
            tname = o.__class__.__name__
            try:
                crc = binascii.crc32(o.crc, crc) & 0xffffffff
            except AttributeError:
                pass
            if isinstance(o, Define):
                s[tname].append(o)
                if o.autoreply:
                    s[tname].append(self.autoreply_block(o.name, o))
            elif isinstance(o, Option):
                s[tname][o.option] = o.value
            elif type(o) is list:
                for o2 in o:
                    if isinstance(o2, Service):
                        s['Service'].append(o2)
            elif (isinstance(o, Enum) or
                  isinstance(o, Typedef) or
                  isinstance(o, Using) or
                  isinstance(o, Union)):
                s['types'].append(o)
            else:
                if tname not in s:
                    raise ValueError('Unknown class type: {} {}'
                                     .format(tname, o))
                s[tname].append(o)

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
                if d[:-8]+'_dump' not in msgs:
                    raise ValueError('{} missing dump message'
                                     .format(d))
                continue

            if d in svcs:
                continue
            if d+'_reply' in msgs:
                s['Service'].append(Service(d, d+'_reply'))
            else:
                raise ValueError(
                    '{} missing reply message ({}) or service definition'
                    .format(d, d+'_reply'))

        return s

    def process_imports(self, objs, in_import, result):
        imported_objs = []
        for o in objs:
            # Only allow the following object types from imported file
            if in_import and not (isinstance(o, Enum) or
                                  isinstance(o, Union) or
                                  isinstance(o, Typedef) or
                                  isinstance(o, Import) or
                                  isinstance(o, Using)):
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
                crc = crc_block_combine(t.block, crc)
                return foldup_blocks(t.block, crc)
            except AttributeError:
                pass
    return crc


def foldup_crcs(s):
    for f in s:
        f.crc = foldup_blocks(f.block,
                              binascii.crc32(f.crc) & 0xffffffff)


#
# Main
#
def main():
    if sys.version_info < (3, 5,):
        log.exception('vppapigen requires a supported version of python. '
                      'Please use version 3.5 or greater. '
                      'Using {}'.format(sys.version))
        return 1

    cliparser = argparse.ArgumentParser(description='VPP API generator')
    cliparser.add_argument('--pluginpath', default=""),
    cliparser.add_argument('--includedir', action='append'),
    cliparser.add_argument('--outputdir', action='store'),
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

    if args.output_module == 'C':
        s = parser.process(parsed_objects)
    else:
        result = parser.process_imports(parsed_objects, False, result)
        s = parser.process(result)

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
        log.exception('Error importing output plugin: {}, {}'
                      .format(module_path, err))
        return 1

    result = plugin.run(args, filename, s)
    if result:
        print(result, file=args.output)
    else:
        log.exception('Running plugin failed: {} {}'
                      .format(filename, result))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
