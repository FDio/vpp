#!/usr/bin/env python3
#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pprint
import framework

from vpp_papi import FuncWrapper, VPP

from framework import VppTestCase, VppTestRunner
from vpp_lo_interface import VppLoInterface


class TestApiServiceCatalog(VppTestCase):
    """ TestApiServiceCatalog
    """

    def get_values(self, fields):
        values = {}
        for field in fields:
            if field.startswith('bool '):
                values[field] = [True, False]
            elif field[0] == 'u' and (' is_' in field or ' use_' in field):
                values[field] = [1, 0]
            else:
                values[field] = []
        return values

    def test_api_service_catalog(self):
        fields = set()
        for api in dir(self.vapi.vpp._api):
            try:
                fn = getattr(self.vapi.vpp._api, api)

                if isinstance(fn, FuncWrapper):
                    args = fn.__doc__.split(', ')
                    try:
                        args.remove('u16 _vl_msg_id')
                        args.remove('u32 client_index')
                        args.remove('u32 context')
                    except ValueError:
                        pass
                    for arg in args:
                        fields.add(arg)
                    print('%s(%s)' % (fn.__name__, ', '.join(args)))
            except AttributeError:
                pass
        print('fields:')
        print('\n'.join(sorted(fields)))
        print('values:')
        pprint.pprint(self.get_values(sorted(fields)))
        print('Calling api...')
        for api in dir(self.vapi.vpp._api):
            try:
                fn = getattr(self.vapi.vpp._api, api)
                print(fn)
                if isinstance(fn, FuncWrapper):
                    rv = self.vapi.fn()
                    print (rv)
            except AttributeError:
                pass


class TestApi(VppTestCase):
    """test_api.TestApi(VppTestCase) https://gerrit.fd.io/r/18273"""

    def test_sw_interface_dump(self):

        # don't use vpp_lo_interface.  It restricts lo instantiation.
        lo0 = self.vapi.create_loopback()
        lo1 = self.vapi.create_loopback()
        print(lo0)
        print(lo1)
        lo10 = self.vapi.create_loopback_instance(is_specified=1,
                                                  user_instance=10)
        print(lo10)
        print("\n%s" % self.vapi.cli('show interface'))
        d = self.vapi.sw_interface_dump(
                                        name_filter="loop1")
        print('dump: %s' % [x.interface_name for x in d])


if __name__ == '__main__':
    framework.main(testRunner=VppTestRunner)

