#
# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from socket import inet_pton, inet_ntop, AF_INET6, AF_INET


class VPPFormat(object):
    @staticmethod
    def format_vl_api_ip6_prefix_t(args):
        prefix, len = args.split('/')
        return {'prefix': {'address': inet_pton(AF_INET6, prefix)},
                'len': int(len)}

    @staticmethod
    def unformat_vl_api_ip6_prefix_t(args):
        return "{}/{}".format(inet_ntop(AF_INET6, args.prefix.address),
                              args.len)

    @staticmethod
    def format_vl_api_ip4_prefix_t(args):
        prefix, len = args.split('/')
        return {'prefix': {'address': inet_pton(AF_INET, prefix)},
                'len': int(len)}

    @staticmethod
    def unformat_vl_api_ip4_prefix_t(args):
        return "{}/{}".format(inet_ntop(AF_INET, args.prefix.address),
                              args.len)

    @staticmethod
    def format_vl_api_ip6_address_t(args):
        return {'address': inet_pton(AF_INET6, args)}

    @staticmethod
    def format_vl_api_ip4_address_t(args):
        return {'address': inet_pton(AF_INET, args)}

    @staticmethod
    def format_vl_api_address_t(args):
        try:
            return {'un': {'ip6': {'address': inet_pton(AF_INET6, args)}},
                    'af': int(1)}
        except Exception as e:
            return {'un': {'ip4': {'address': inet_pton(AF_INET, args)}},
                    'af': int(0)}

    @staticmethod
    def unformat_vl_api_address_t(arg):
        if arg.af == 1:
            return inet_ntop(AF_INET6, arg.un.ip6.address)
        if arg.af == 0:
            return inet_ntop(AF_INET, arg.un.ip4.address)
        raise

    @staticmethod
    def format_vl_api_prefix_t(args):
        prefix, len = args.split('/')
        return {'address': VPPFormat.format_vl_api_address_t(prefix),
                'address_length': int(len)}

    @staticmethod
    def unformat_vl_api_prefix_t(arg):
        if arg.address.af == 1:
            return "{}/{}".format(inet_ntop(AF_INET6,
                                            arg.address.un.ip6.address),
                                  arg.address_length)
        if arg.address.af == 0:
            return "{}/{}".format(inet_ntop(AF_INET,
                                            arg.address.un.ip4.address),
                                  arg.address_length)
        raise

    @staticmethod
    def format_u8(args):
        try:
            return int(args)
        except Exception as e:
            return args.encode()

    @staticmethod
    def format(typename, args):
        try:
            return getattr(VPPFormat, 'format_' + typename)(args)
        except AttributeError:
            # Default
            return (int(args))

    @staticmethod
    def unformat_bytes(args):
        try:
            return args.decode('utf-8')
        except Exception as e:
            return args

    @staticmethod
    def unformat_list(args):
        s = '['
        for f in args:
            t = type(f).__name__
            if type(f) is int:
                s2 = str(f)
            else:
                s2 = VPPFormat.unformat_t(t, f)
            s += '{} '.format(s2)
        return s[:-1] + ']'

    @staticmethod
    def unformat(args):
        s = ''
        return VPPFormat.unformat_t(type(args).__name__, args)
        '''
        for i, f in enumerate(args):
            print('F', f)
            t = type(f).__name__
            if type(f) is int:
                s2 = str(f)
            else:
                s2 = VPPFormat.unformat_t(t, f)
            s += '{} {} '.format(args._fields[i], s2)
        return s[:-1]
        '''

    @staticmethod
    def unformat_t(typename, args):
        try:
            return getattr(VPPFormat, 'unformat_' + typename)(args)
        except AttributeError:
            # Type without explicit override
            return VPPFormat.unformat(args)

        # Default handling
        return args
