#!/usr/bin/env python

from __future__ import print_function
import ply.lex as lex
import ply.yacc as yacc
import sys
import argparse
import logging
import binascii

#
# VPP API language
#
#
# [<flags>] define <name> { block };
# vl_api_version n.n.n
# enum <name> { enum_block };
#
# - Set of messages defined with "define {};" blocks.
# - Traditional C types, self-defined types.
#   Self-defined types, defined with "typedef {};" blocks. "typeonly define {};"
#                       for backwards compatibility
# - Defaults can be specified ( Mandatory versus Optional?)
#
# - Flags? Change to option inside of block?
# - Enums
# - Character string versus bytearray. string?
# - enums and types _inside_ of message scope? => no.
# - Service definitions. Describe streaming API and RPC style.
# - Arrays are represented with [length, data]
# - Deprecated flag support
#   options { manual_print, manual_endian, deprecated };
#
# Support for importing type definitions and enums.
#
#typedef enum {
#    RED = 1,
#    BLUE,
#} fib_enum_t;
#define show_version {
#  int major;
#  int minor;
#  string version[256];
#  bool enabled = True;
#  fib_enum_t flags = RED;
#};

# Global scope options:
# import <filename>
# string version = "STRING_LITERAL"


reserved = {
    'define'        : 'DEFINE',
    'typedef'       : 'TYPEDEF',
    'union'         : 'UNION',
    'enum'          : 'ENUM',
    'typeonly'      : 'TYPEONLY',
    'manual_print'  : 'MANUAL_PRINT',
    'manual_endian' : 'MANUAL_ENDIAN',
    'dont_trace'    : 'DONT_TRACE',
    'autoreply'     : 'AUTOREPLY',
    'u8'            : 'U8',
    'u16'           : 'U16',
    'u32'           : 'U32',
    'u64'           : 'U64',
    'i8'            : 'I8',
    'i16'           : 'I16',
    'i32'           : 'I32',
    'i64'           : 'I64',
    'bool'          : 'BOOL',
    'string'        : 'STRING',
    'import'        : 'IMPORT',
    'vl_api_version': 'VERSION',
}

tokens = ['STRING_LITERAL',
          'ID', 'NUM'] + list(reserved.values())

t_ignore_LINE_COMMENT = '//.*'

def t_NUM(t):
    r'0[xX][0-9a-fA-F]+|\d+'
    base = 16 if t.value.startswith('0x') else 10
    t.value = int(t.value, base)
    return t

def t_ID(t):
    r'[a-zA-Z_][a-zA-Z_0-9]*'
    t.type = reserved.get(t.value,'ID')    # Check for reserved words
    return t

# C string
def t_STRING_LITERAL(t):
   r'\"([^\\\n]|(\\.))*?\"'
   t.value = str(t.value).replace("\"", "")
   return t

# C or C++ comment (ignore)
def t_comment(t):
    r'(/\*(.|\n)*?\*/)|(//.*)'
    pass

# Error handling rule
def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

    # Define a rule so we can track line numbers
def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

literals = "{}[];=.,"

# A string containing ignored characters (spaces and tabs)
t_ignore  = ' \t'


#
# Globals
#
class globals():
    input_filename = ''
    parse_error = False

class Iterator(type):
    def __iter__ (self):
        return self.iter()

class Typedef():
    def __init__(self, name, flags, block):
        self.name = name
        self.flags = flags
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)

class Union():
    def __init__(self, block):
        print('Block', block)
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff

    def __repr__(self):
        return str(self.block)

class Define():
    def __init__(self, name, flags, block):
        self.name = name
        self.flags = flags
        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff
        self.typeonly = False
        self.dont_trace = False
        self.manual_print = False
        self.manual_endian = False
        self.autoreply = False
        for f in flags:
            if f == 'typeonly':
                self.typeonly = True
            elif f == 'dont_trace':
                self.dont_trace = True
            elif f == 'manual_print':
                self.manual_print = True
            elif f == 'manual_endian':
                self.manual_endian = True
            elif f == 'autoreply':
                self.autoreply = True

    def __repr__(self):
        return self.name + str(self.flags) + str(self.block)

class Enum():
    def __init__(self, name, block):
        self.name = name
        count = 0
        for i, b in enumerate(block):
            if type (b) is list:
                count = b[1]
            else:
                block[i] = [b, count]
                count += 1

        self.block = block
        self.crc = binascii.crc32(str(block)) & 0xffffffff

    def __repr__(self):
        return self.name + str(self.block)

class Import():
    def __init__(self, filename):
        self.filename = filename

    def __repr__(self):
        return self.filename

class Assignment():
    def __init__(self, assignment):
        self.assignment = assignment
        self.crc = binascii.crc32(str(assignment)) & 0xffffffff

    def __repr__(self):
        return str(self.assignment)

class Version():
    def __init__(self, major, minor, patch):
        self.major = major
        self.minor = minor
        self.patch = patch

    def __repr__(self):
        return str([self.major, self.minor, self.patch])

def p_slist(p):
    '''slist : stmt
             | slist stmt'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]

def p_stmt(p):
    '''stmt : define
            | typedef
            | assignment
            | import
            | version
            | enum'''
    p[0] = p[1]

def p_version(p):
    '''version : VERSION NUM  '.' NUM '.' NUM '''
    p[0] = Version(p[2], p[4], p[6])

def p_import(p):
    '''import : IMPORT STRING_LITERAL ';' '''
    p[0] = Import(p[2])

def p_enum(p):
    '''enum : ENUM ID '{' enum_statements '}' ';' '''
    p[0] = Enum(p[2], p[4])

def p_define(p):
    '''define : DEFINE ID '{' block_statements_opt '}' ';' '''
    p[0] = Define(p[2], [], p[4])

def p_define_flist(p):
    '''define : flist DEFINE ID '{' block_statements_opt '}' ';' '''
    p[0] = Define(p[3], p[1], p[5])

def p_flist(p):
    '''flist : flag
             | flist flag'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]

def p_flag(p):
    '''flag : MANUAL_PRINT
            | MANUAL_ENDIAN
            | DONT_TRACE
            | TYPEONLY
            | AUTOREPLY'''
    if len(p) == 1: return
    p[0] = p[1]

def p_typedef(p):
    '''typedef : TYPEDEF ID '{' union_block_statements '}' ';' '''
    p[0] = Typedef(p[2], [], p[4])

def p_block_statements_opt(p):
    '''block_statements_opt : block_statements'''
    p[0] = p[1]

def p_union_block_statements(p):
    '''union_block_statements : union
                        | block_statement
                        | union_block_statements block_statement
                        | '''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]
def p_union(p):
    '''union : UNION '{' block_statements '}' ';' '''
    p[0] = Union(p[3])

def p_block_statements(p):
    '''block_statements : block_statement
                        | block_statements block_statement'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]

def p_block_statement(p):
    '''block_statement : declaration
                       | assignment '''
    p[0] = p[1]

def p_enum_statements(p):
    '''enum_statements : enum_statement
                        | enum_statements enum_statement'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]

def p_enum_statement(p):
    '''enum_statement : ID '=' NUM ','
                      | ID ',' '''
    if len(p) == 5:
        p[0] = [p[1], p[3]]
    else:
        p[0] = p[1]

def p_declaration(p):
    '''declaration : type_specifier ID ';'
                   | type_specifier ID '[' NUM ']' ';'
                   | type_specifier ID '[' ID ']' ';' ''' # Remove this
    if len(p) == 4:
        p[0] = [p[1], p[2]]
    elif len(p) == 7:
        p[0] = [p[1], p[2], p[4]]
    else:
        # error
        print('ERROR ERROR')

def p_assigment(p):
    '''assignment : type_specifier ID '=' assignee ';' '''
    p[0] = Assignment([p[1], p[2], p[4]])

def p_assignee(p):
    '''assignee : NUM
                | STRING_LITERAL '''
    p[0] = p[1]

def p_type_specifier(p):
    '''type_specifier : U8
                      | U16
                      | U32
                      | U64
                      | I8
                      | I16
                      | I32
                      | I64
                      | BOOL
                      | STRING'''
    p[0] = p[1]

def p_typedef_specifier(p):
    '''type_specifier : ID '''
    p[0] = p[1]

# Error rule for syntax errors
def p_error(p):
    if (p):
        print("Syntax error in %s at line %s illegal token: %s" %
              (globals.input_filename, p.lineno, p.value))
    else:
        print("Syntax error")
    globals.parse_error = True

#### MAIN ####

def parse_file(fd, log):
    data = fd.read()
    result = parser.parse(data, debug=log)
    return result

def process(objs):
    s = {}
    s['defines'] = []
    s['typedefs'] = []
    s['imports'] = []
    s['assignments'] = []
    s['version'] = []
    s['enums'] = []
    for o in objs:
        if isinstance(o, Define):
            if o.typeonly:
                s['typedefs'].append(o)
            else:
                s['defines'].append(o)
                if o.autoreply:
                    autoreply_block = [['u32', 'context'], ['i32', 'retval']]
                    reply = Define(o.name + '_reply', [], autoreply_block)
                    s['defines'].append(reply)
        elif isinstance(o, Import):
            s['imports'].append(o)
        elif isinstance(o, Assignment):
            s['assignments'].append(o)
        elif isinstance(o, Version):
            s['version'].append(o)
        elif isinstance(o, Enum):
            s['enums'].append(o)
        elif isinstance(o, Typedef):
            for b in o.block:
                if isinstance(b, Union):
                    print('UNION')
            s['typedefs'].append(o)
    return s

def add_msg_id(s):
    for o in s:
        o.block.insert(0, ['u16', '_vl_msg_id'])
    return s

def getcrc(s):
    return binascii.crc32(str(s)) & 0xffffffff

#
# Main
#

parser = argparse.ArgumentParser(description='VPP API generator')
parser.add_argument('--input', type=argparse.FileType('r'), default=sys.stdin)
parser.add_argument('--output', nargs='?', type=argparse.FileType('w'),
                    default=sys.stdout)

parser.add_argument('output_module', nargs = '?', default = 'C')
parser.add_argument('--debug', action='store_true')
parser.add_argument('--show-name', nargs=1)
args = parser.parse_args()

# Filename
if args.show_name:
    filename = args.show_name[0]
elif args.input != sys.stdin:
    filename = args.input.name
else:
    filename = ''
globals.input_file = filename

# Build the lexer
lexer = lex.lex()

# Build the parser
parser = yacc.yacc(tabmodule='vppapigentab', debug=True)

logging.basicConfig()
log = logging.getLogger('vppapigen')

result = parse_file(args.input, log)
if globals.parse_error:
    print('Parsing failed.')
    sys.exit(-1)

#
# Build a list of objects. Hash of lists.
s = process(result)

#
# Add msg_id field
s['defines'] = add_msg_id(s['defines'])

#
# Deal with imports
r = []
for i in s['imports']:
    with open(i.filename) as fd:
        r += parse_file(fd, log)

import_s = process(r)
if len(import_s['defines']) > 0:
    # Only accept typedefs in imported files for now
    print('Message defines are ignored imported files')

s['typedefs'] += import_s['typedefs']

file_crc = getcrc(s)

#
# Debug
if args.debug:
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    for t in s['defines']:
        pp.pprint([t.name, t.flags, t.block])
    for t in s['typedefs']:
        pp.pprint([t.name, t.flags, t.block])

#
# Generate representation
#
import importlib

try:
    plugin = importlib.import_module( args.output_module )
except ImportError:
    print('No such output plugin definition', plugin)

result = plugin.run(filename, s, file_crc)
if result:
    print (result, file = args.output)
