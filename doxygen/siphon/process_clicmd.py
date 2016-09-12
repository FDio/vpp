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

class SiphonCLICMD(process.Siphon):

    name = "clicmd"
    identifier = "VLIB_CLI_COMMAND"

    def __init__(self, *args, **kwargs):
        super(SiphonCLICMD, self).__init__(*args, **kwargs)
        self._parser = parsers.MacroInitializer()


    # Output renderers

    def index_sort_key(self, group, dec):
        if group in dec and 'group_label' in dec[group]:
            return dec[group]['group_label']
        return group

    def _index_entry(self, meta, item):
        v = item["value"]
        return "* j[%s](@ref %s)\n" % (v['path'], meta["label"])

    def sort_key(self, item):
        return item['value']['path']


# Register our processor
process.siphons["clicmd"] = SiphonCLICMD
