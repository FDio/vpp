#!/usr/bin/env python
# Copyright (c) 2016 Comcast Cable Communications Management, LLC.
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

# Filter for vpe.api to make it Doxygenish.

import sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <filename>\n" % (sys.argv[0]))
    sys.exit(1)

patterns = [
    # Search for "define" blocks and treat them as structs
    ( re.compile(r"^.*(manual_.[^\s]+\s+)?define\s+(?P<name>[^\s]+)"), r"typedef struct vl_api_\g<name>_t"),

    # For every "brief" statement at the start of a comment block, add an
    # xref with whatever is on the same line. This gives us an index page
    # with all the API methods in one place.
    # XXX Commented out for now; works but duplicates the brief text in the
    # struct documentation
    #( re.compile(r"/\*\*\s*(?P<b>[\\@]brief)\s+(?P<c>.+)(\*/)$"), r'/** @xrefitem api "" "VPP API" \g<c> \g<b> \g<c>'),  # capture inline comment close
    #( re.compile(r"/\*\*\s*(?P<b>[\\@]brief)\s+(?P<c>.+)$"), r'/** @xrefitem api "" "VPP API" \g<c> \g<b> \g<c>'),

    # Since structs don't have params, replace @param with @tparam
    ( re.compile("[\\@]param\\b"), "@tparam"),
]

with open(sys.argv[1]) as fd:
    for line in fd:
        str = line[:-1] # strip \n
        for p in patterns:
            str = p[0].sub(p[1], str)
        sys.stdout.write(str+"\n")
