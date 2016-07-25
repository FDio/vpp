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

# Filter for .c files to make various preprocessor tricks Doxygenish

import os, sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <filename>\n" % (sys.argv[0]))
    sys.exit(1)

replace_patterns = [
    # Search for CLIB_PAD_FROM_TO(...); and replace with padding
    # #define CLIB_PAD_FROM_TO(from,to) u8 pad_##from[(to) - (from)]
    ( re.compile("(?P<m>CLIB_PAD_FROM_TO)\s*[(](?P<from>[^,]+),\s*(?P<to>[^)]+)[)]"),
        r"/** Padding. */ u8 pad_\g<from>[(\g<to>) - (\g<from>)]" ),

]


filename = sys.argv[1]
cwd = os.getcwd()
if filename[0:len(cwd)] == cwd:
    filename = filename[len(cwd):]
    if filename[0] == "/":
        filename = filename[1:]

with open(filename) as fd:
    line_num = 0

    for line in fd:
        line_num += 1
        str = line[:-1] # filter \n

        # Look for search/replace patterns
        for p in replace_patterns:
            str = p[0].sub(p[1], str)

        sys.stdout.write(str+"\n")

# All done
