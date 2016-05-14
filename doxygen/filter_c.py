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

# Filter for .c files to make various preprocessor tricks Doxygenish

import sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <filename>\n" % (sys.argv[0]))
    sys.exit(1)

patterns = [
    # Search for VLIB_CLI_COMMAND, extract its parameter and add a docblock for it
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (\g<name>) */ vlib_cli_command_t \g<name>"),

    # Search for VLIB_REGISTER_NODE, extract its parameter and add a docblock for it
    ( re.compile("(?P<m>VLIB_REGISTER_NODE)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (\g<name>) */ vlib_node_registration_t \g<name>"),

    # Search for VLIB_INIT_FUNCTION, extract its parameter and add a docblock for it
    ( re.compile("(?P<m>VLIB_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"), r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>"),
    ( re.compile("(?P<m>VLIB_DECLARE_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"), r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>"),

    # Search for VLIB_LOOP_ENTER_FUNCTION, extract the 1st parameter (ignore any others) and add a docblock for it
    ( re.compile("(?P<m>VLIB_MAIN_LOOP_ENTER_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ _vlib_main_loop_enter_\g<name>"),
    ( re.compile("(?P<m>VLIB_MAIN_LOOP_EXIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ _vlib_main_loop_exit_\g<name>"),

    # Search for VLIB_CONFIG_FUNCTION, extract the 1st parameter (ignore any others) and add a docblock for it
    ( re.compile("(?P<m>VLIB_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>\"[^\"]+\")(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),
    ( re.compile("(?P<m>VLIB_EARLY_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>\"[^\"]+\")(,[^)]*)?[)]"), r"/** @brief (@em constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),

    # Search for "format_thing" and "unformat_thing" when used as a function pointer and add parens
    ( re.compile("(?P<pre>(^|,)\s*)(?P<name>(un)?format_[a-zA-Z0-9_]+)(?P<post>\s*(,|$))") , r"\g<pre>\g<name>()\g<post>" ),
]

with open(sys.argv[1]) as fd:
    for line in fd:
        str = line[:-1] # filter \n
        for p in patterns:
            str = p[0].sub(p[1], str)
        sys.stdout.write(str+"\n")
