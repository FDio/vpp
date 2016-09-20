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

import generate, re

# Register our regexp
generate.siphon_patterns.append((
    re.compile("(?P<m>VLIB_CONFIG_FUNCTION)\s*"
        '[(](?P<fn>[a-zA-Z0-9_]+)\s*,\s*"(?P<name>[^"]*)"[)]'),
    "syscfg"
))
