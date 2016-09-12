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

# Generate syscfg formatted output

import process, parsers

class SiphonSYSCFG(process.Siphon):

    name = "syscfg"
    identifier = "VLIB_CONFIG_FUNCTION"

    def __init__(self, *args, **kwargs):
        super(SiphonSYSCFG, self).__init__(*args, **kwargs)
        self._parser = parsers.ParseFunctionMacroStmt()


# Register our processor
process.siphons["syscfg"] = SiphonSYSCFG
