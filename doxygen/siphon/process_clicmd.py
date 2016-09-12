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

    def index_sort_key(self, group):
        _global = self._cmds['_global']
        if group not in self._group:
            return group
        (directory, file) = self._group[group]

        if file in _global and 'group_label' in _global[file]:
            return _global[file]['group_label']

        if directory in _global and 'group_label' in _global[directory]:
            return _global[directory]['group_label']

        return group

    def item_sort_key(self, item):
        return item['value']['path']

    def item_label(self, group, item):
        return "_".join((
            self.name,
            self.sanitize_label(self._cmds[group][item]['value']['path'])
        ))


# Register our processor
process.siphons["clicmd"] = SiphonCLICMD
