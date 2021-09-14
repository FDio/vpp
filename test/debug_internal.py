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
import gc
import pprint
import vpp_papi
from vpp_papi_provider import VppPapiProvider
import objgraph
from pympler import tracker
tr = tracker.SummaryTracker()

"""
  Internal debug module

  The module provides functions for debugging test framework
"""


def on_tear_down_class(cls):
    gc.collect()
    tr.print_diff()
    objects = gc.get_objects()
    counter = 0
    with open(cls.tempdir + '/python_objects.txt', 'w') as f:
        interesting = [
            o for o in objects
            if isinstance(o, (VppPapiProvider, vpp_papi.VPP))]
        del objects
        gc.collect()
        for o in interesting:
            objgraph.show_backrefs([o], max_depth=5,
                                   filename="%s/%s.png" %
                                   (cls.tempdir, counter))
            counter += 1
            refs = gc.get_referrers(o)
            pp = pprint.PrettyPrinter(indent=2)
            f.write("%s\n" % pp.pformat(o))
            for r in refs:
                try:
                    f.write("%s\n" % pp.pformat(r))
                except:
                    f.write("%s\n" % type(r))
