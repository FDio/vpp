#!/usr/bin/env python3
#  Copyright (c) 2020. Vinci Consulting Corp. All Rights Reserved.
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

import glob
import inspect
import os
import re
import sys


class ContentRenderer:
    def __init__(self, ws_root, output_dir):
        self.ws_root = ws_root
        self.output_dir = output_dir

    def plugin_dir(self):
        return os.path.join(self.ws_root, "src/plugins")

    def render(self):
        raise NotImplementedError


class PluginRenderer(ContentRenderer):

    def _render_entry(self, output_file, entry):
        description = "<no-description-found>"
        # we use glob because a plugin can (ioam for now)
        # define the plugin definition in
        # a further subdirectory.
        path = os.path.join(self.plugin_dir(), entry.name, '**')
        for f in glob.iglob(path, recursive=True):
            if not f.endswith('.c'):
                continue
            with open(f, "r", encoding="utf-8") as src:
                for match in self.regex.finditer(src.read()):
                    description = "%s" % (match.group(1))

        output_file.write(f"* {entry.name} - {description}\n")

    def render(self):
        pattern = r'VLIB_PLUGIN_REGISTER\s?\(\)\s*=\s*{.*\.description\s?=\s?"([^"]*)".*};'  # noqa: 501
        self.regex = re.compile(pattern, re.MULTILINE | re.DOTALL)
        fname = os.path.join(self.output_dir, "plugin_list.inc")
        with open(fname, "w") as output_file:
            with os.scandir(self.plugin_dir()) as pdir:
                for entry in sorted(pdir, key=lambda entry: entry.name):
                    if not entry.name.startswith('.') and entry.is_dir():
                        self._render_entry(output_file, entry)


renderers = [PluginRenderer]


def main():
    if len(sys.argv) != 3:
        print("You need to pass WS_ROOT and OUTPUT_DIR")
        exit(1)

    print("rendering dynamic includes...")
    for renderer in renderers:
        renderer(*sys.argv[1:]).render()
    print("done.")


if __name__ == "__main__":
    main()
