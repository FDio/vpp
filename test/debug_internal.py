# Copyright (c) 2021 Cisco and/or its affiliates.
#
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

# This is a standalone library not depending on any GPL-licensed code.

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
