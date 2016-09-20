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

# Looks for preprocessor macros with struct initializers and siphons them
# off into another file for later parsing; ostensibly to generate
# documentation from struct initializer data.

import os, sys, re, argparse, json, subprocess

DEFAULT_OUTPUT = "build-root/docs/siphons"
DEFAULT_PREFIX = os.getcwd()
DEFAULT_CPP = "cpp"
DEFAULT_CPPARGS = ""
DEFAULT_USECPP = True

ap = argparse.ArgumentParser()
ap.add_argument("--output", '-o', metavar="directory", default=DEFAULT_OUTPUT,
        help="Output directory for .siphon files [%s]" % DEFAULT_OUTPUT)
ap.add_argument("--input-prefix", metavar="path", default=DEFAULT_PREFIX,
        help="Prefix to strip from input pathnames [%s]" % DEFAULT_PREFIX)
ap.add_argument("--cpp", metavar="path", default=DEFAULT_CPP,
        help="Path to the C pre-processor [%s]" % DEFAULT_CPP)
ap.add_argument("--cppargs", metavar="args", default=DEFAULT_CPPARGS,
        help="Arguments to pass to the C pre-processor [%s]" % DEFAULT_CPPARGS)
_usecpp = ap.add_mutually_exclusive_group(required=False)
_usecpp.add_argument("--usecpp", action='store_true',  dest='usecpp',
        help="Use the C pre-processor [%s]" % DEFAULT_USECPP)
_usecpp.add_argument("--no-usecpp", action='store_false', dest='usecpp',
        help="Do not use the C pre-processor")
ap.set_defaults(usecpp=DEFAULT_USECPP)
ap.add_argument("input", nargs='+', metavar="input_file",
        help="Input C source files")
args = ap.parse_args()

# If usecpp==True then validate the pre-processor works
if args.usecpp:
    cpp = args.cpp
    if not os.path.isfile(cpp):
        # Check if it's in the PATH
        for path in os.environ['PATH'].split(os.pathsep):
            file = os.path.join(path, cpp)
            if os.path.isfile(file):
                cpp = file
                args.cpp = file
                break
    if not os.path.isfile(cpp):
        print "C Pre-processor '%s' does not exist." % cpp
        sys.exit(1)
    if not os.access(cpp, os.X_OK):
        print "C Pre-processor '%s' is not executable." % cpp
        sys.exit(1)
    # Spawn CPP
    cmd = [ cpp, '-x', 'c' ]
    if len(args.cppargs):
        cmd += args.cppargs.split(" ")
    p = subprocess.Popen(cmd, bufsize=-1, close_fds=True, executable=cpp,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd="/")
    # Send some input to CPP to test if #define works
    (p_stdout, p_stderr) = p.communicate(input="#define test true\ntest\n")
    if p.returncode != 0:
        print "C Pre-processor '%s' does not appear to work." % cpp
        sys.exit(1)
    # Read back from the process until we see "test" which indicates CPP
    # works as expected
    found = False
    for line in iter(p_stdout.splitlines()):
        if line == "true":
            found = True
    if not found:
        print "C Pre-processor '%s' does not appear to work." % cpp
        sys.exit(1)


"""Patterns that match the start of code blocks we want to siphon"""
siphon_patterns = [
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), "clicmd" ),
]

"""Matches a siphon comment block start"""
siphon_block_start = re.compile("^\s*/\*\?\s*(.*)$")

"""Matches a siphon comment block stop"""
siphon_block_stop = re.compile("^(.*)\s*\?\*/\s*$")

"""Siphon block directive delimiter"""
siphon_block_delimiter = "%%"

"""Matches a siphon block directive such as '%clicmd:group_label Debug CLI%'"""
siphon_block_directive = re.compile("(%s)\s*([a-zA-Z0-9_:]+)\s+(.*)\s*(%s)" % \
        (siphon_block_delimiter, siphon_block_delimiter))

"""Matches the start of an initializer block"""
siphon_initializer = re.compile("\s*=")

"""Matches a directive from the C pre-processor"""
cpp_directive = re.compile('^# ([0-9]+) "([^"]+)"')

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

# Collated output for each siphon
output = {}

# Build a list of known siphons
known_siphons = []
for item in siphon_patterns:
	siphon = item[1]
	if siphon not in known_siphons:
		known_siphons.append(siphon)

# Setup information for siphons we know about
for siphon in known_siphons:
	output[siphon] = {
            "file": "%s/%s.siphon" % (args.output, siphon),
            "global": {},
            "items": [],
        }

# Pre-process file names in case they indicate a file with
# a list of files
files = []
for filename in args.input:
    if filename.startswith('@'):
        with open(filename[1:], 'r') as fp:
            lines = fp.readlines()
            for line in lines:
                files.append(line.strip())
            lines = None
    else:
        files.append(filename)

# Iterate all the input files we've been given
for filename in files:
    # Strip the current directory off the start of the
    # filename for brevity
    if filename[0:len(args.input_prefix)] == args.input_prefix:
        filename = filename[len(args.input_prefix):]
        if filename[0] == "/":
            filename = filename[1:]

    # Work out the abbreviated directory name
    directory = os.path.dirname(filename)
    if directory[0:2] == "./":
        directory = directory[2:]
    elif directory[0:len(args.input_prefix)] == args.input_prefix:
        directory = directory[len(args.input_prefix):]
    if directory[0] == "/":
    	directory = directory[1:]

    # Open the file and explore its contents...
    sys.stderr.write("Siphoning from %s...\n" % filename)
    directives = {}

    siphon = None
    close_siphon = None
    siphon_block = ""
    in_block = False
    line_num = 0
    siphon_line = 0

    fd = None
    cpppipe = None
    if args.usecpp:
        # Spawn CPP
        cmd = [ args.cpp, '-x', 'c', '-C', '-w' ]
        if len(args.cppargs):
            cmd += args.cppargs.split(" ")
        cmd.append(filename)
        sys.stderr.write("cmd: '%s'\n" % " ".join(cmd))
        cpppipe = subprocess.Popen(cmd,
            bufsize=-1,
            close_fds=True,
            executable=args.cpp,
            stdin=None,
            stdout=subprocess.PIPE)
        fd = cpppipe.stdout
    else:
        fd = open(filename)

    for line in fd:
        line_num += 1
        str = line[:-1] # filter \n

        if args.usecpp and len(str) and str[0] == '#':
            # Look for pre-processor directives

            m = cpp_directive.search(str)
            if m is not None:
                # Update the line number
                line_num = int(m.group(1))
                # If the filename is not us, skip to the next line
                cppfile = m.group(2)
                if cppfile is not None:
                    if cppfile != filename:
                        continue


        """See if there is a block directive and if so extract it"""
        def process_block_directive(str, directives):
            m = siphon_block_directive.search(str)
            if m is not None:
                k = m.group(2)
                v = m.group(3).strip()
                directives[k] = v
                # Return only the parts we did not match
                return str[0:m.start(1)] + str[m.end(4):]

            return str

        def process_block_prefix(str):
            if str.startswith(" * "):
                str = str[3:]
            elif str == " *":
                str = ""
            return str
            
        if not in_block:
            # See if the line contains the start of a siphon doc block
            m = siphon_block_start.search(str)
            if m is not None:
                in_block = True
                t = m.group(1)

                # Now check if the block closes on the same line
                m = siphon_block_stop.search(t)
                if m is not None:
                    t = m.group(1)
                    in_block = False

                # Check for directives
                t = process_block_directive(t, directives)

                # Filter for normal comment prefixes
                t = process_block_prefix(t)

                # Add what is left
                siphon_block += t

                # Skip to next line
                continue

        else:
            # Check to see if we have an end block marker
            m = siphon_block_stop.search(str)
            if m is not None:
                in_block = False
                t = m.group(1)
            else:
                t = str

            # Check for directives
            t = process_block_directive(t, directives)

            # Filter for normal comment prefixes
            t = process_block_prefix(t)

            # Add what is left
            siphon_block += t + "\n"

            # Skip to next line
            continue


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
            # See if we should end the siphon here - do we have balanced
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
            siphon_name = close_siphon[0]

            # Copy directives for the file
            details = {}
            for key in directives:
                if ":" in key:
                    (sn, label) = key.split(":")
                    if sn == siphon_name:
                        details[label] = directives[key]
                else:
                    details[key] = directives[key]

            # Copy details for this block
            details['file'] = filename
            details['line_start'] = siphon_line
            details['line_end'] = line_num
            details['siphon_block'] = siphon_block.strip()

            # Some defaults
            if "group" not in details:
                if "group_label" in details:
                    # use the filename since group labels are mostly of file scope
                    details['group'] = details['file']
                else:
                    details['group'] = directory

            if "group_label" not in details:
                details['group_label'] = details['group']

            details["block"] = close_siphon[1]

            # Store the item
            output[siphon_name]['items'].append(details)

            # All done
            close_siphon = None
            siphon_block = ""

    # Update globals
    for key in directives.keys():
        if ':' not in key:
            continue

        if filename.endswith("/dir.dox"):
            # very special! use the parent directory name
            l = directory
        else:
            l = filename

        (sn, label) = key.split(":")

        if sn not in output:
            output[sn] = {}
        if 'global' not in output[sn]:
            output[sn]['global'] = {}
        if l not in output[sn]['global']:
            output[sn]['global'][l] = {}
        if 'file' not in output[sn]:
            output[sn]['file'] = "%s/%s.siphon" % (args.output, sn)
        if 'items' not in output[sn]:
            output[sn]['items'] = []

        output[sn]['global'][l][label] = directives[key]

    if args.usecpp:
        # Wait for the thing to finish, complain if there were errors
        cpppipe.wait()
        if cpppipe.returncode != 0:
            sys.stderr.write("Error running C pre-processor on file '%s'." %
                filename)
            sys.exit(1)


# Write out the data
for siphon in output.keys():
    sys.stderr.write("Saving siphon %s...\n" % siphon)
    s = output[siphon]
    with open(s['file'], "a") as fp:
        json.dump(s, fp, separators=(',', ': '), indent=4, sort_keys=True)

# All done
