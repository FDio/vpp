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

import os, sys, re, argparse
import pprint

DEFAULT_OUTPUT = "build-root/docs/siphons"
DEFAULT_PREFIX = os.getcwd()

ap = argparse.ArgumentParser()
ap.add_argument("--output", '-o', metavar="directory", default=DEFAULT_OUTPUT,
        help="Output directory for .siphon files [%s]" % DEFAULT_OUTPUT)
ap.add_argument("--input-prefix", metavar="path", default=DEFAULT_PREFIX,
        help="Prefix to strip from input pathnames [%s]" % DEFAULT_PREFIX)
ap.add_argument("input", nargs='+', metavar="input_file",
        help="Input C source files")
args = ap.parse_args()

"""Patterns that match the start of code blocks wre want to siphon"""
siphon_patterns = [
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), "clicmd" ),
]

"""Matches the start of an initializer block"""
siphon_initializer = re.compile("\s*=")

"""
count open and close braces in str
return (0, index) when braces were found and count becomes 0.
index indicates the position at which the last closing brace was
found.
return (-1, -1) if a closing brace is found before any opening one.
return (count, -1) if not all opening braces are closed, count is the
current depth
"""
def count_braces(str, count=0, found=False):
    for index in range(0, len(str)):
        if str[index] == '{':
            count += 1;
            found = True
        elif str[index] == '}':
            if count == 0:
                # means we never found an open brace
                return (-1, -1)
            count -= 1;

        if count == 0 and found:
            return (count, index)

    return (count, -1)

# Cache of file descriptors
files = {}

# Iterate all the input files we've been given
for filename in args.input:
    # Strip the current directory off the start of the
    # filename for brevity
    if filename[0:len(args.input_prefix)] == args.input_prefix:
        filename = filename[len(args.input_prefix):]
        if filename[0] == "/":
            filename = filename[1:]

    # Open the file and explore its contents...
    with open(filename) as fd:
        siphon = None
        close_siphon = None
        line_num = 0
        siphon_line = 0

        for line in fd:
            line_num += 1
            str = line[:-1] # filter \n

            if siphon is None:
                # Look for blocks we need to siphon
                for p in siphon_patterns:
                    if p[0].match(str):
                        siphon = [ p[1], str + "\n", 0 ]
                        siphon_line = line_num

                        # see if we have an initializer
                        m = siphon_initializer.search(str)
                        if m is not None:
                            # count the braces on this line
                            (count, index) = count_braces(str[m.start():])
                            siphon[2] = count
                            # TODO - it's possible we have the initializer all on the first line
                            # we should check for it, but also account for the possibility that
                            # the open brace is on the next line
                            #if count == 0:
                            #    # braces balanced
                            #    close_siphon = siphon
                            #    siphon = None
                        else:
                            # no initializer: close the siphon right now
                            close_siphon = siphon
                            siphon = None
            else:
                # See if we should end the siphon here - do we have balance
                # braces?
                (count, index) = count_braces(str, count=siphon[2], found=True)
                if count == 0:
                    # braces balanced - add the substring and close the siphon
                    siphon[1] += str[:index+1] + ";\n"
                    close_siphon = siphon
                    siphon = None
                else:
                    # add the whole string, move on
                    siphon[2] = count
                    siphon[1] += str + "\n"

            if close_siphon is not None:
                # Write the siphoned contents to the right place
                f = "%s/%s.siphon" % (args.output, close_siphon[0])

                # get a handle on the file
                if f in files:
                    fp = files[f]
                else:
                    fp = open(f, "a+")
                    files[f] = fp

                # write our details out
                fp.write("file = \"%s\";\n" % filename)
                fp.write("line_start = %d;\n" % siphon_line)
                fp.write("line_end = %d;\n" % line_num)
                fp.write(close_siphon[1])
                fp.write("=%=%=\n")

                close_siphon = None

# Close any open files
for f in files:
        files[f].close()

# All done
