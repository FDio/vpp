#!/usr/bin/env python3

from vpp_papi import VPP
import cmd
from socket import inet_pton, inet_ntop, AF_INET6, AF_INET

import argparse

## usage [in <f1> ... in <fn>] [out <fn>] [script] [json]
## [plugin_path <path>][default-socket][socket-name <name>]
## [plugin_name_filter <filter>][chroot prefix <path>]

'''
parser = argparse.ArgumentParser(description='VPP API Tester.')
parser.add_argument('integers', metavar='N', type=int, nargs='+',
                    help='an integer for the accumulator')
parser.add_argument('socket-name', dest='socketname', action='store_const',
                    help='Unix Domain Socket name')

args = parser.parse_args()
print(args.accumulate(args.integers))
'''

def event_handler(message):
    print('EVENT HANDLER', message)

vpp = VPP(use_socket=True)

vpp.connect(name='vat', chroot_prefix='foo')
vpp.register_event_callback(event_handler)

class Format:
    def format_vl_api_ip6_prefix_t(args):
        prefix, len = args.split('/')
        return {'prefix': {'address': inet_pton(AF_INET6, prefix)},
                'len': int(len)}

    def unformat_vl_api_ip6_prefix_t(args):
        return "{}/{}".format(inet_ntop(AF_INET6, args.prefix.address), args.len)

    def format_vl_api_ip4_prefix_t(args):
        prefix, len = args.split('/')
        return {'prefix': {'address': inet_pton(AF_INET, prefix)},
                'len': int(len)}

    def unformat_vl_api_ip4_prefix_t(args):
        return "{}/{}".format(inet_ntop(AF_INET, args.prefix.address), args.len)

    def format_vl_api_ip6_address_t(args):
        return {'address': inet_pton(AF_INET6, args)}

    def format_vl_api_ip4_address_t(args):
        return {'address': inet_pton(AF_INET, args)}

    def format_u8(args):
        try:
            return int(args)
        except:
            return args.encode()

    def format(typename, args):
        try:
            return getattr(Format, 'format_' + typename)(args)
        except AttributeError:
            return (int(args))

    def unformat_bytes(args):
        try:
            return args.decode('utf-8')
        except:
            return args

    def unformat_list(args):
        s = '['
        for f in args:
            t = type(f).__name__
            if type(f) is int:
                s2 = str(f)
            else:
                s2 = Format.unformat(t, f)
            s += '{} '.format(s2)
        return s[:-1] + ']'

    def unformat_type(args):
        s = ''
        for i, f in enumerate(args):
            t = type(f).__name__
            if type(f) is int:
                s2 = str(f)
            else:
                s2 = Format.unformat(t, f)
            s += '{} {} '.format(args._fields[i], s2)
        return s[:-1]

    def unformat(typename, args):
        try:
            return getattr(Format, 'unformat_' + typename)(args)
        except AttributeError:
            # Type without explicit override
            return Format.unformat_type(args)

        # Default handling
        return args

def mapargs(name, args):
    msg = vpp.messages[name]
    fields = msg.fields
    fields_by_name = msg.field_by_name
    i = 0
    a = {}
    while i < len(args):
        if args[i] in fields_by_name:
            # Convert args[i+1] to correct type
            index = fields.index(args[i])
            t = msg.fieldtypes[index]
            a[args[i]] = Format.format(t, args[i+1])
        i += 2
    return a

def mapresult(res):
    s = ""
    if type(res) is list:
        for r in res:
            s += Format.unformat_type(r)
            s += '\n'
    else:
        return Format.unformat_type(res)
    return s

class VATShell(cmd.Cmd):
    intro = 'Welcome to the VAT shell.   Type help or ? to list commands.\n'
    prompt = 'vat# '
    file = None

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.commands = sorted(vpp.messages.keys())

    def do_exit(self, s):
        'Exit the VAT shell'
        print()
        return True

    def help_exit(self):
        print ("Exit the interpreter.")
        print ("You can also use the Ctrl-D shortcut.")

    do_EOF = do_exit
    help_EOF= help_exit

    def default(self, line):
        args = line.split()

        try:
            f = getattr(vpp.api, args[0])
        except AttributeError:
            print('command not found {}'.format(line))
            return

        #try:
        a = mapargs(args[0], args[1:])
        #except:
        #    print('invalid arguments {}'.format(line))
        #    return

        rv = f(**a)
        print(mapresult(rv))

    # if last word is a valid field, show completion for that field
    def completedefault(self, text, line, begidx, endidx):
        args = line.split()
        fields = vpp.messages[args[0]].fields
        if args[-1] in fields:
            i = fields.index(args[-1])
            t = vpp.messages[args[0]].fieldtypes[i]
            if t == 'u32':
                return ['0', '4294967296']
            if t == 'u8':
                return ['0', '255']
            print('TYPE', t)
        return [param for param in fields if param.startswith(text)]

    def completenames(self, text, line, begidx, endidx):
        if text:
            return [command for command in self.commands
                    if command.startswith(text)]

    def do_help(self, arg):
        if not arg:
            for k in self.commands:
                print(k)
        else:
            if arg in vpp.messages:
                print(vpp.messages[arg].msgdef)
                print(str(vpp.messages[arg]))
                print(repr(vpp.messages[arg]))
        super(VATShell, self).do_help(arg)

if __name__ == '__main__':
    VATShell().cmdloop()
