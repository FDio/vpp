#!/usr/bin/env python

from __future__ import print_function
import ply.lex as lex
import ply.yacc as yacc
import sys
import argparse
import logging
import binascii
import os

# Ensure we don't leave temporary files around
sys.dont_write_bytecode = True

#
# VPP API language
#

# Global dictionary of new types (including enums)
global_types = {}
global_crc = 0


def global_type_add(name):
    '''Add new type to the dictionary of types '''
    type_name = 'vl_api_' + name + '_t'
    if type_name in global_types:
        raise KeyError('Type is already defined: {}'.format(name))
    global_types[type_name] = True


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

    def t_NUM(self, t):
        r'0[xX][0-9a-fA-F]+|\d+'
        base = 16 if t.value.startswith('0x') else 10
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


class Service():
    def __init__(self, caller, reply, events=[], stream=False):
        self.caller = caller
        self.reply = reply
        self.stream = stream
        self.events = events


class Typedef():
    def __init__(self, name, flags, block):
        global global_crc
        self.name = name
        self.flags = flags
        if type(block) is list:
            self.typedef_alias = False
        else:
            self.typedef_alias = True
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff
        global_crc = binascii.crc32(str(block), global_crc)
        self.manual_print = False
        self.manual_endian = False
        for f in flags:
            if f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True
        global_type_add(name)

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Union():
    def __init__(self, name, block):
        self.type = 'Union'
        self.manual_print = False
        self.manual_endian = False
        global global_crc
        self.name = name
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff
        global_crc = binascii.crc32(str(block), global_crc)
        global_type_add(name)

    def __repr__(self):
        return str(self.block)


class Define():
    def __init__(self, name, flags, block):
        global global_crc
        self.name = name
        self.flags = flags
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff
        global_crc = binascii.crc32(str(block), global_crc)
        self.dont_trace = False
        self.manual_print = False
        self.manual_endian = False
        self.autoreply = False
        self.singular = False
        for f in flags:
            if f == 'dont_trace':
                self.dont_trace = True
            elif f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True
            elif f == 'autoreply':
                self.autoreply = True

        for b in block:
            if isinstance(b, Option):
                if b[1] == 'singular' and b[2] == 'true':
                    self.singular = True
                block.remove(b)

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)


class Enum():
    def __init__(self, name, block, enumtype='u32'):
        global global_crc
        self.name = name
        self.enumtype = enumtype

        count = 0
        for i, b in enumerate(block):
            if type(b) is list:
                count = b[1]
            else:
                count += 1
                block[i] = [b, count]

        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff
        global_crc = binascii.crc32(str(block), global_crc)
        global_type_add(name)

    def __repr__(self):
        return self.name + str(self.block)


class Import():
    def __init__(self, filename):
        self.filename = filename

        # Deal with imports
        parser = VPPAPI(filename=filename)
        dirlist = dirlist_get()
        f = filename
        for dir in dirlist:
            f = os.path.join(dir, filename)
            if os.path.exists(f):
                break
        with open(f) as fd:
            self.result = parser.parse_file(fd, None)

    def __repr__(self):
        return self.filename


class Option():
    def __init__(self, option):
        global global_crc
        self.option = option
        self.crc = binascii.crc32(str(option)) & 0xffffffff
        global_crc = binascii.crc32(str(option), global_crc)

    def __repr__(self):
        return str(self.option)

    def __getitem__(self, index):
        return self.option[index]


class Array():
    def __init__(self, fieldtype, name, length):
        self.type = 'Array'
        self.fieldtype = fieldtype
        self.fieldname = name
        if type(length) is str:
            self.lengthfield = length
            self.length = 0
        else:
            self.length = length
            self.lengthfield = None

    def __repr__(self):
        return str([self.fieldtype, self.fieldname, self.length,
                    self.lengthfield])


class Field():
    def __init__(self, fieldtype, name):
        self.type = 'Field'
        self.fieldtype = fieldtype
        self.fieldname = name

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

    def __init__(self, filename, logger):
        self.filename = filename
        self.logger = logger
        self.fields = []

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
        p[0] = Import(p[2])

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
            p[0] = Typedef(p[3], p[1], p[5])
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

    def p_typedef2(self, p):
        '''typedef : TYPEDEF type_specifier ID ';' '''
        p[0] = Typedef(p[3], [], p[2])

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

    def p_declaration(self, p):
        '''declaration : type_specifier ID ';' '''
        if len(p) != 4:
            self._parse_error('ERROR')
        self.fields.append(p[2])
        p[0] = Field(p[1], p[2])

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
        p[0] = Option([p[1], p[2], p[4]])

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
        p[0] = Union(p[2], p[4])

    # Error rule for syntax errors
    def p_error(self, p):
        if p:
            self._parse_error(
                'before: %s' % p.value,
                self._coord(lineno=p.lineno))
        else:
            self._parse_error('At end of input', self.filename)


class VPPAPI(object):

    def __init__(self, debug=False, filename='', logger=None):
        self.lexer = lex.lex(module=VPPAPILexer(filename), debug=debug)
        self.parser = yacc.yacc(module=VPPAPIParser(filename, logger),
                                write_tables=False, debug=debug)
        self.logger = logger

    def parse_string(self, code, debug=0, lineno=1):
        self.lexer.lineno = lineno
        return self.parser.parse(code, lexer=self.lexer, debug=debug)

    def parse_file(self, fd, debug=0):
        data = fd.read()
        return self.parse_string(data, debug=debug)

    def autoreply_block(self, name):
        block = [Field('u32', 'context'),
                 Field('i32', 'retval')]
        return Define(name + '_reply', [], block)

    def process(self, objs):
        s = {}
        s['Option'] = {}
        s['Define'] = []
        s['Service'] = []
        s['types'] = []
        s['Import'] = []
        for o in objs:
            tname = o.__class__.__name__
            if isinstance(o, Define):
                s[tname].append(o)
                if o.autoreply:
                    s[tname].append(self.autoreply_block(o.name))
            elif isinstance(o, Option):
                s[tname][o[1]] = o[2]
            elif type(o) is list:
                for o2 in o:
                    if isinstance(o2, Service):
                        s['Service'].append(o2)
            elif isinstance(o, Enum) or isinstance(o, Typedef) or isinstance(o, Union):
                s['types'].append(o)
            else:
                if tname not in s:
                    raise ValueError('Unknown class type: {} {}'.format(tname, o))
                s[tname].append(o)

        msgs = {d.name: d for d in s['Define']}
        svcs = {s.caller: s for s in s['Service']}
        replies = {s.reply: s for s in s['Service']}
        seen_services = {}

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
                                  isinstance(o, Import)):
                continue
            if isinstance(o, Import):
                self.process_imports(o.result, True, result)
            else:
                result.append(o)

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


#
# Main
#
def main():
    cliparser = argparse.ArgumentParser(description='VPP API generator')
    cliparser.add_argument('--pluginpath', default=""),
    cliparser.add_argument('--includedir', action='append'),
    cliparser.add_argument('--input', type=argparse.FileType('r'),
                           default=sys.stdin)
    cliparser.add_argument('--output', nargs='?', type=argparse.FileType('w'),
                           default=sys.stdout)

    cliparser.add_argument('output_module', nargs='?', default='C')
    cliparser.add_argument('--debug', action='store_true')
    cliparser.add_argument('--show-name', nargs=1)
    args = cliparser.parse_args()

    dirlist_add(args.includedir)
    if not args.debug:
        sys.excepthook = exception_handler

    # Filename
    if args.show_name:
        filename = args.show_name[0]
    elif args.input != sys.stdin:
        filename = args.input.name
    else:
        filename = ''

    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
    else:
        logging.basicConfig()
    log = logging.getLogger('vppapigen')

    parser = VPPAPI(debug=args.debug, filename=filename, logger=log)
    parsed_objects = parser.parse_file(args.input, log)

    # Build a list of objects. Hash of lists.
    result = []
    parser.process_imports(parsed_objects, False, result)
    s = parser.process(result)

    # Add msg_id field
    s['Define'] = add_msg_id(s['Define'])

    file_crc = global_crc & 0xffffffff

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
    import imp

    # Default path
    pluginpath = ''
    if not args.pluginpath:
        cand = []
        cand.append(os.path.dirname(os.path.realpath(__file__)))
        cand.append(os.path.dirname(os.path.realpath(__file__)) +
                    '/../share/vpp/')
        for c in cand:
            c += '/'
            if os.path.isfile('{}vppapigen_{}.py'.format(c, args.output_module.lower())):
                pluginpath = c
                break
    else:
        pluginpath = args.pluginpath + '/'
    if pluginpath == '':
        raise Exception('Output plugin not found')
    module_path = '{}vppapigen_{}.py'.format(pluginpath, args.output_module.lower())

    try:
        plugin = imp.load_source(args.output_module, module_path)
    except Exception, err:
        raise Exception('Error importing output plugin: {}, {}'
                        .format(module_path, err))

    result = plugin.run(filename, s, file_crc)
    if result:
        print(result, file=args.output)
    else:
        raise Exception('Running plugin failed: {} {}'
                        .format(filename, result))


if __name__ == '__main__':
    main()
