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
import os.path
import re


class ContentRenderer:
    name = ""
    curr_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
    vpp_root = curr_path.rsplit("/", 2)[0]
    output_dir = f"{vpp_root}/docs/dynamic_includes/"

    def render(self):
        raise NotImplementedError


class PluginRenderer(ContentRenderer):
    name = "plugin_list.inc"

    plugin_dir = f"{ContentRenderer.vpp_root}/src/plugins"

    pattern = r'VLIB_PLUGIN_REGISTER\s?\(\)\s*=\s*{.*\.description\s?=\s?"([^"]*)".*};'  # noqa: 501
    regex = re.compile(pattern, re.MULTILINE | re.DOTALL)

    def render(self):
        with open(f"{self.__class__.output_dir}{self.__class__.name}",
                  "w") as output:
            with os.scandir(self.__class__.plugin_dir) as pdir:
                for entry in sorted(pdir, key=lambda entry: entry.name):
                    if not entry.name.startswith('.') and entry.is_dir():
                        description = "<no-description-found>"
                        # we use glob because a plugin can (ioam for now)
                        # define the plugin definition in
                        # a further subdirectory.
                        for f in glob.iglob(f'{self.__class__.plugin_dir}/'
                                            f'{entry.name}/**',
                                            recursive=True):
                            if f.endswith('.c'):
                                with open(f, "r", encoding="utf-8") \
                                        as src:
                                    for match in self.__class__.regex.finditer(
                                            src.read()):
                                        description = "%s" % (match.group(1))

                        output.write(f"* {entry.name} - {description}\n")


# if this list grows substantially, we can move the classes to
# a folder and import them.
renderers = [PluginRenderer,
             ]


def main():
    print("rendering dynamic includes...")
    for renderer in renderers:
        renderer().render()
    print("done.")


if __name__ == "__main__":
    main()
