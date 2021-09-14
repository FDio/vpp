#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
from multiprocessing import Pipe
import sys
import os
from framework import VppDiedError, VppTestCase, KeepAliveReporter


class SanityTestCase(VppTestCase):
    """ Sanity test case - verify whether VPP is able to start """
    cpus = [0]

    # don't ask to debug SanityTestCase
    @classmethod
    def wait_for_enter(cls, pid=0):
        pass

    @classmethod
    def _debug_quit(cls):
        try:
            cls.vpp.poll()
        except AttributeError:
            pass


if __name__ == '__main__':
    rc = 0
    tc = SanityTestCase
    x, y = Pipe()
    reporter = KeepAliveReporter()
    reporter.pipe = y
    try:
        tc.setUpClass()
    except VppDiedError:
        rc = -1
    else:
        try:
            tc.tearDownClass()
        except Exception:
            rc = -1
    x.close()
    y.close()

    if rc == 0:
        print('Sanity test case passed.')
    else:
        print('Sanity test case failed.')

    sys.exit(rc)
