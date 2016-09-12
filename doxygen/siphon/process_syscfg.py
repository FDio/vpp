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

# Generate clicmd formatted output

import process, parsers

class SiphonSYSCFG(process.Siphon):

    name = "syscfg"
    identifier = "VLIB_CONFIG_FUNCTION"

    def __init__(self):
        super(SiphonSYSCFG, self).__init__()
        self._parser = parsers.ParseFunctionMacroStmt()


    # Output renderers

    def index_sort_key(self, group, dec):
        if group in dec and 'group_label' in dec[group]:
            return dec[group]['group_label']
        return group

    def index_header(self):
        s = "# Startup configuration\n"
        s += "\n[TOC]\n"
        return s

    def header(self, group, dec):
        if group in dec and 'group_label' in dec[group]:
            label = dec[group]['group_label']
        else:
            label = group
        return "\n@page %s %s\n" % (self.page_label(group), label)

    def format(self, meta, item):
        label = meta["label"]
        s = "\n@section %s %s\n\n" % (label, item['name'])

        # Extracted from the code in /*? ... ?*/ blocks
        if "siphon_block" in item["meta"]:
            sb = item["meta"]["siphon_block"]

            if len(sb) > 0:
                s += "### Description\n\n%s\n\n" % sb

        # Gives some developer-useful linking
        if "item" in meta or "function" in item:
            s += "### Declaration and implementation\n\n"

            if "item" in meta:
                s += "Declaration: @ref %s (@ref %s line %d)\n\n" % \
                    (meta['item'], meta["file"], int(item["meta"]["line_start"]))

            if "function" in item:
                s += "Implementation: @ref %s.\n\n" % item["function"]

        return s


# Register our processor
process.siphons["syscfg"] = SiphonSYSCFG
