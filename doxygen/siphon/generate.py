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

# Generate .siphon source fragments for later processing

import logging
import os, sys, re, json

"""List of (regexp, siphon_name) tuples for matching the start of C
   initializer blocks in source files. Each siphon class registers
   themselves on tihs list."""
siphon_patterns = []

class Generate(object):
    """Matches a siphon comment block start"""
    siphon_block_start = re.compile("^\s*/\*\?\s*(.*)$")

    """Matches a siphon comment block stop"""
    siphon_block_stop = re.compile("^(.*)\s*\?\*/\s*$")

    """Siphon block directive delimiter"""
    siphon_block_delimiter = "%%"

    """Matches a siphon block directive such as
       '%clicmd:group_label Debug CLI%'"""
    siphon_block_directive = re.compile("(%s)\s*([a-zA-Z0-9_:]+)\s+(.*)\s*(%s)" % \
            (siphon_block_delimiter, siphon_block_delimiter))

    """Matches the start of an initializer block"""
    siphon_initializer = re.compile("\s*=")

    """Collated output for each siphon"""
    output = None

    """Directory prefix to strip from input filenames to keep things tidy."""
    input_prefix = None

    """List of known siphons"""
    known_siphons = None

    """Logging handler"""
    log = None


    def __init__(self, output_directory, input_prefix):
        super(Generate, self).__init__()
        self.log = logging.getLogger("siphon.generate")

        # Build a list of known siphons
        self.known_siphons = []
        for item in siphon_patterns:
            siphon = item[1]
            if siphon not in self.known_siphons:
                self.known_siphons.append(siphon)

        # Setup information for siphons we know about
        self.output = {}
        for siphon in self.known_siphons:
            self.output[siphon] = {
                    "file": "%s/%s.siphon" % (output_directory, siphon),
                    "global": {},
                    "items": [],
                }

        self.input_prefix = input_prefix


    """
    count open and close braces in str
    return (0, index) when braces were found and count becomes 0.
    index indicates the position at which the last closing brace was
    found.
    return (-1, -1) if a closing brace is found before any opening one.
    return (count, -1) if not all opening braces are closed, count is the
    current depth
    """
    def count_braces(self, str, count=0, found=False):
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

    def parse(self, filename):
        # Strip the current directory off the start of the
        # filename for brevity
        if filename[0:len(self.input_prefix)] == self.input_prefix:
            filename = filename[len(self.input_prefix):]
            if filename[0] == "/":
                filename = filename[1:]

        # Work out the abbreviated directory name
        directory = os.path.dirname(filename)
        if directory[0:2] == "./":
            directory = directory[2:]
        elif directory[0:len(self.input_prefix)] == self.input_prefix:
            directory = directory[len(self.input_prefix):]
        if directory[0] == "/":
            directory = directory[1:]

        # Open the file and explore its contents...
        self.log.info("Siphoning from %s." % filename)
        directives = {}
        with open(filename) as fd:
            siphon = None
            close_siphon = None
            siphon_block = ""
            in_block = False
            line_num = 0
            siphon_line = 0

            for line in fd:
                line_num += 1
                str = line[:-1] # filter \n

                """See if there is a block directive and if so extract it"""
                def process_block_directive(str, directives):
                    m = self.siphon_block_directive.search(str)
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
                    m = self.siphon_block_start.search(str)
                    if m is not None:
                        in_block = True
                        t = m.group(1)

                        # Now check if the block closes on the same line
                        m = self.siphon_block_stop.search(t)
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
                    m = self.siphon_block_stop.search(str)
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
                            m = self.siphon_initializer.search(str)
                            if m is not None:
                                # count the braces on this line
                                (count, index) = \
                                    self.count_braces(str[m.start():])
                                siphon[2] = count
                                # TODO - it's possible we have the
                                # initializer all on the first line
                                # we should check for it, but also
                                # account for the possibility that
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
                    # See if we should end the siphon here - do we have
                    # balanced braces?
                    (count, index) = self.count_braces(str,
                            count=siphon[2], found=True)
                    if count == 0:
                        # braces balanced - add the substring and
                        # close the siphon
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
                    details['directory'] = directory
                    details['line_start'] = siphon_line
                    details['line_end'] = line_num
                    details['siphon_block'] = siphon_block.strip()
                    details["block"] = close_siphon[1]

                    # Store the item
                    self.output[siphon_name]['items'].append(details)

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

                if sn not in self.output:
                    self.output[sn] = {}
                if 'global' not in self.output[sn]:
                    self.output[sn]['global'] = {}
                if l not in self.output[sn]['global']:
                    self.output[sn]['global'][l] = {}

                self.output[sn]['global'][l][label] = directives[key]

    def deliver(self):
        # Write out the data
        for siphon in self.output.keys():
            self.log.info("Saving siphon data %s." % siphon)
            s = self.output[siphon]
            with open(s['file'], "a") as fp:
                json.dump(s, fp,
                    separators=(',', ': '), indent=4, sort_keys=True)

