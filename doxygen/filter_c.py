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

import os, sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <filename>\n" % (sys.argv[0]))
    sys.exit(1)

replace_patterns = [
    # Search for VLIB_CLI_COMMAND, extract its parameters and add a docblock for it
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>) */ vlib_cli_command_t \g<name>"),
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<qual>[^)]*)[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>) */ \g<qual> vlib_cli_command_t \g<name>"),

    # Search for VLIB_REGISTER_NODE, extract its parameters and add a docblock for it
    ( re.compile("(?P<m>VLIB_REGISTER_NODE)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>) */ vlib_node_registration_t \g<name>"),
    ( re.compile("(?P<m>VLIB_REGISTER_NODE)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<qual>[^)]*)[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>) */ \g<qual> vlib_node_registration_t \g<name>"),

    # Search for VLIB_INIT_FUNCTION, extract its parameter and add a docblock for it
    ( re.compile("(?P<m>VLIB_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"),
        r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>"),
    ( re.compile("(?P<m>VLIB_DECLARE_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"),
        r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>"),

    # Search for VLIB_LOOP_ENTER_FUNCTION, extract the parameters and add a docblock for it
    ( re.compile("(?P<m>VLIB_MAIN_LOOP_ENTER_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"),
        r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ _vlib_main_loop_enter_\g<name>"),
    ( re.compile("(?P<m>VLIB_MAIN_LOOP_EXIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"),
        r"/** @brief (@em constructor) \g<m> (@ref \g<name>) */ _vlib_main_loop_exit_\g<name>"),

    # Search for VLIB_CONFIG_FUNCTION, extract the parameters and add a docblock for it
    ( re.compile("(?P<m>VLIB_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>\"[^\"]+\")(,[^)]*)?[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),
    ( re.compile("(?P<m>VLIB_EARLY_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>\"[^\"]+\")(,[^)]*)?[)]"),
        r"/** @brief (@em constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),

    # Search for "format_thing" and "unformat_thing" when used as a function pointer and add parens
    ( re.compile("(?P<pre>(^|,)\s*)(?P<name>(un)?format_[a-zA-Z0-9_]+)(?P<post>\s*(,|$))"),
        r"\g<pre>\g<name>()\g<post>" ),

    # Search for CLIB_PAD_FROM_TO(...); and replace with padding
    # #define CLIB_PAD_FROM_TO(from,to) u8 pad_##from[(to) - (from)]
    ( re.compile("(?P<m>CLIB_PAD_FROM_TO)\s*[(](?P<from>[^,]+),\s*(?P<to>[^)]+)[)]"),
        r"/** Padding. */ u8 pad_\g<from>[(\g<to>) - (\g<from>)]" ),

]


filename = sys.argv[1]
cwd = os.getcwd()
if filename[0:len(cwd)] == cwd:
    filename = filename[len(cwd):]
    if filename[0] == "/":
        filename = filename[1:]

with open(filename) as fd:
    line_num = 0

    for line in fd:
        line_num += 1
        str = line[:-1] # filter \n

        # Look for search/replace patterns
        for p in replace_patterns:
            str = p[0].sub(p[1], str)

        sys.stdout.write(str+"\n")

# All done
