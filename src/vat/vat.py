#!/usr/bin/env python3

import cmd
from socket import inet_pton, inet_ntop, AF_INET6, AF_INET
import json
import argparse
import ipaddress
import shlex
from io import StringIO
import pprint
import sys
import os
try:
    from vpp_papi import VPP
except ImportError:
    # Perhaps we are in the source directory
    sys.path.append('src/vpp-api/python')
    from vpp_papi import VPP

interfaces = {}


def startup_init(vpp):
    # Create initial interface to ifindex mapping
    rv = vpp.api.sw_interface_dump()
    for i in rv:
        name = i.interface_name.split(b'\0', 1)[0].decode('utf8')
        interfaces[name] = i.sw_if_index

    # Register for changes
    rv = vpp.api.want_interface_events(enable_disable=1, pid=os.getpid())


# From stackoverflow
class VATPrettyPrinter(pprint.PrettyPrinter):
    def format_namedtuple(self, object, stream, indent,
                          allowance, context, level):
        # Code almost equal to _format_dict, see pprint code
        write = stream.write
        write(object.__class__.__name__ + '(')
        object_dict = object._asdict()
        length = len(object_dict)
        if length:
            # We first try to print inline,
            # and if it is too large then we print it on multiple lines
            inline_stream = StringIO()
            self.format_namedtuple_items(object_dict.items(), inline_stream,
                                         indent, allowance + 1, context, level,
                                         inline=True)
            max_width = self._width - indent - allowance
            if len(inline_stream.getvalue()) > max_width:
                self.format_namedtuple_items(object_dict.items(), stream,
                                             indent, allowance + 1, context,
                                             level, inline=False)
            else:
                stream.write(inline_stream.getvalue())
        write(')')

    def format_namedtuple_items(self, items, stream, indent, allowance,
                                context, level, inline=False):
        # Code almost equal to _format_dict_items, see pprint code
        indent += self._indent_per_level
        write = stream.write
        last_index = len(items) - 1
        if inline:
            delimnl = ', '
        else:
            delimnl = ',\n' + ' ' * indent
            write('\n' + ' ' * indent)
        for i, (key, ent) in enumerate(items):
            last = i == last_index
            write(key + '=')
            self._format(ent, stream, indent + len(key) + 2,
                         allowance if last else 1,
                         context, level)
            if not last:
                write(delimnl)

    def _format(self, object, stream, indent, allowance, context, level):
        # We dynamically add the types of our namedtuple and namedtuple like
        # classes to the _dispatch object of pprint that maps classes to
        # formatting methods
        # We use a simple criteria (_asdict method) that allows us to use the
        # same formatting on other classes but a more precise one is possible
        if hasattr(object, '_asdict') and type(object).__repr__ not in self._dispatch:
            self._dispatch[type(object).__repr__] = VATPrettyPrinter.format_namedtuple
        super()._format(object, stream, indent, allowance, context, level)


pp = VATPrettyPrinter(indent=2)


def event_handler(message, event):
    pp.pprint(event)


class Format:
    def format_vl_api_ip6_address_t(args):
        return ipaddress.IPv6Address(args)

    def format_vl_api_ip4_address_t(args):
        return ipaddress.IPv4Address(args)

    def format_vl_api_ip6_prefix_t(args):
        return ipaddress.IPv6Network(args)

    def format_vl_api_ip4_prefix_t(args):
        return ipaddress.IPv4Network(args)

    def format_vl_api_interface_index_t(args):
        try:
            return int(args)
        except ValueError:
            try:
                return interfaces[args]
            except KeyError:
                print('No such interface', args)
                raise

    def format_string(args):
        return args

    def format_u8(args):
        try:
            return int(args)
        except Exception():
            return args.encode()

    def format(typename, args):
        try:
            return getattr(Format, 'format_' + typename)(args)
        except AttributeError:
            return (int(args))


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
            try:
                a[args[i]] = Format.format(t, args[i+1])
            except Exception():
                raise
            i += 2
    return a


class VATShell(cmd.Cmd):
    intro = 'Welcome to the VAT shell.   Type help or ? to list commands.\n'
    prompt = 'vat# '
    file = None

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.commands = sorted(vpp.services.keys())
        self.pp = VATPrettyPrinter(indent=2)

    def do_exit(self, s):
        'Exit the VAT shell'
        print()
        return True

    def do_exec(self, s):
        'Run a VPP debug cli command'
        rv = vpp.api.cli_inband(cmd=s)
        if rv.retval == 0:
            print(rv.reply)
        else:
            print('Command {} failed with {}'.format(s, rv.retval))

    def help_exit(self):
        print("Exit the interpreter.")
        print("You can also use the Ctrl-D shortcut.")

    do_EOF = do_exit
    help_EOF = help_exit

    def emptyline(self):
        pass

    def default(self, line):
        args = shlex.split(line)

        try:
            f = getattr(vpp.api, args[0])
        except AttributeError:
            print('command not found {}'.format(line))
            return

        try:
            a = mapargs(args[0], args[1:])
        except Exception():
            print('invalid arguments {}'.format(line))
            return

        rv = f(**a)
        self.pp.pprint(rv)

    # if last word is a valid field, show completion for that field
    def completedefault(self, text, line, begidx, endidx):
        args = line.split()

        fields = vpp.messages[args[0]].fields[3:]  # Skip header fields
        fieldtypes = vpp.messages[args[0]].fieldtypes[3:]
        lastarg = None
        if len(args) >= 2:
            if args[-1] in fields:
                lastarg = args[-1]
            elif args[-2] in fields:
                lastarg = args[-2]
        if lastarg:
            i = fields.index(lastarg)
            t = fieldtypes[i]
            if t == 'u32':
                return ['0', '4294967296']
            if t == 'u8':
                return ['0', '255']
            if t == 'u16':
                return ['0', '65535']
            if t == 'vl_api_interface_index_t':
                if text:
                    return [intf for intf in list(interfaces)
                            if intf.startswith(text)]
                return list(interfaces)
        else:
            return [param for param in fields if param.startswith(text)]
        return []

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


def socket_connect(socket_name, apifiles):
    if socket_name:
        vpp = VPP(use_socket=True, server_address=socket_name, apifiles=apifiles)
    else:
        vpp = VPP(use_socket=True, apifiles=apifiles)
    try:
        vpp.connect(name='vat')
    except Exception:
        sys.exit(-1)
    return vpp


def sharedmemory_connect(prefix, find_library, apifiles):
    from vpp_papi.vpp_transport_shmem import VppClientLibraryName
    if find_library:
        for root, dirs, files in os.walk('.'):
            if VppClientLibraryName in files:
                library_path = root + '/'
                break
        vpp = VPP(library_path=library_path, apifiles=apifiles)
    else:
        vpp = VPP()
    vpp.connect(name='vat', chroot_prefix=prefix)
    return vpp


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VPP API Tester CLI.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--socket-name", help="API socket name")
    group.add_argument("--shared-memory", help="Shared memory prefix")
    parser.add_argument("--find-library", "-f", action='store_true',
                        help="Look hard for the vppapiclient library")
    parser.add_argument("--apidir", help="Directory for API files")
    args = parser.parse_args()

    if args.apidir:
        apifiles = []
        for root, dirs, files in os.walk(args.apidir):
            for name in files:
                apifiles.append(os.path.join(root, name))
    else:
        apifiles = None

    if args.shared_memory:
        vpp = sharedmemory_connect(args.shared_memory, args.find_library, apifiles)
    else:
        vpp = socket_connect(args.socket_name, apifiles)
    vpp.register_event_callback(event_handler)
    startup_init(vpp)
    VATShell().cmdloop()
