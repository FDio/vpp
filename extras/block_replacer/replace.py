#!/usr/bin/env python3

# Copyright (c) 2021 Cisco and/or its affiliates.
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

"""A script simplifying replacement of blocks of lines.

A bash solution created by combining these two:
    https://unix.stackexchange.com/a/181215
    https://stackoverflow.com/a/23849180
does not seem to work if the blocks contain complicated characters.
"""

import argparse
import os
import tempfile

def main():
    """Main function for the block replacing script."""

    description = '''Replace a block of lines with another block.

    Both block-to-replace and replacing-block are read from a file.
    The replacement is performed on a file, in-place.
    Only first block occurence is replaced.
    If the block-to-replace is preceded by a partial match,
    it may not be recognized.

    The current implementation uses temporary files,
    created in the working directory.
    if something fails, thise temporary files need to be deleted manually.

    TODO: Preserve target attributes. Maybe https://pypi.org/project/in-place/
'''
    parser = argparse.ArgumentParser(description)
    parser.add_argument(
        u"before", type=str,
        help=u"Path to file containing the old content to replace."
    )
    parser.add_argument(
        u"after", type=str,
        help=u"Path to file containing the new content to replace with."
    )
    parser.add_argument(
        u"targets", metavar=u"target", nargs=u"+", type=str,
        help=u"Paths to file where the replacement should be made."
    )
    args = parser.parse_args()

    do_it(args)


def do_it(args):
    """Read contents, create edited target, replace the original target with it.

    :param args: Parsed command line arguments.
    :type args: Object (typically argparse.Namespace) which contains
        "before", "after" and "target" fields.
    """
    with open(args.before, u"r") as file_in:
        content_before = file_in.readlines()
    before_len = len(content_before)
    with open(args.after, u"r") as file_in:
        content_after = file_in.readlines()

    for target in args.targets:
        with tempfile.NamedTemporaryFile(
            dir=u".", mode=u"w", delete=False
        ) as file_out:
            with open(target, u"r") as file_in:
                # Phase one, searching for content, copying what does not match.
                buffer_lines = list()
                line_index_to_check = 0
                content_found = False
                while 1:
                    line_in = file_in.readline()
                    if not line_in:
                        print(f"{target}: Content not found.")
                        for line_out in buffer_lines:
                            file_out.write(line_out)
                        buffer_lines = list()
                        break
                    if line_in != content_before[line_index_to_check]:
                        line_index_to_check = 0
                        if buffer_lines:
                            for line_out in buffer_lines:
                                file_out.write(line_out)
                            buffer_lines = list()
                        file_out.write(line_in)
                        continue
                    buffer_lines.append(line_in)
                    line_index_to_check += 1
                    if line_index_to_check < before_len:
                        continue
                    # Buffer has the match! Do not write it.
                    content_found = True
                    break
                if not content_found:
                    file_out.close()
                    os.remove(file_out.name)
                    continue
                # Phase two, write the replacement instead.
                for line_out in content_after:
                    file_out.write(line_out)
                # Phase three, copy the rest of the file.
                while 1:
                    line_in = file_in.readline()
                    if not line_in:
                        print(f"{target}: Replacement done.")
                        break
                    file_out.write(line_in)
        os.replace(file_out.name, target)


if __name__ == u"__main__":
    main()
