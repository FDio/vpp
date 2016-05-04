#!/usr/bin/env python

import sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <filename>\n" % (sys.argv[0]))
    sys.exit(1)

patterns = [
    ( re.compile("(?P<m>VLIB_CLI_COMMAND)\s*[(](?P<name>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (constructor) \g<m> (\g<name>) */ vlib_cli_command_t \g<name>"),

    ( re.compile("(?P<m>VLIB_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"), r"/** @brief (constructor) \g<m> (\g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>_"),
    ( re.compile("(?P<m>VLIB_DECLARE_INIT_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+)[)]"), r"/** @brief (constructor) \g<m> (\g<name>) */ vlib_init_function_t * _vlib_init_function_\g<name>"),

    ( re.compile("(?P<m>VLIB_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),
    ( re.compile("(?P<m>VLIB_EARLY_CONFIG_FUNCTION)\s*[(](?P<name>[a-zA-Z0-9_]+),\s*(?P<n>[a-zA-Z0-9_]+)(,[^)]*)?[)]"), r"/** @brief (constructor) \g<m> (\g<name>, \g<n>) */ vlib_config_function_runtime_t _vlib_config_function_\g<name>"),
]

with open(sys.argv[1]) as fd:
    for line in fd:
        str = line
        for p in patterns:
            str = p[0].sub(p[1], str)
        sys.stdout.write(str)
