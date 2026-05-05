# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Meter, Inc.
#
# vppapigen plugin: emits both .vapi.h and .vapi.hpp from one invocation,
# replacing the standalone scripts in src/vpp-api/vapi/ that took JSON input.
#
# Usage: invoked by vppapigen as `vppapigen ... vapi`. Output goes to two
# files in `output_dir`: <module>.vapi.h and <module>.vapi.hpp.

import logging
import os
import sys

# Plugin contract: vppapigen flattens imported types into s["types"] /
# s["Define"] when this is True, so the generated header is self-contained
# and matches the JSON-driven output 1:1.
process_imports = True


def run(output_dir, apifilename, s):
    if not output_dir:
        sys.stderr.write("Missing --outputdir argument")
        return None

    # Lazy imports so the plugin loader doesn't pay the cost on plugins it
    # doesn't run, and so a syntax error in the emitter doesn't blow up
    # plugin discovery for the whole tool.
    from vppapigen_vapi_c import parser_from_ast, write_vapi_h
    from vppapigen_vapi_cpp import parser_from_ast_cpp, write_vapi_hpp

    basename = os.path.basename(apifilename)
    h_filename = os.path.join(output_dir, basename + ".vapi.h")
    hpp_filename = os.path.join(output_dir, basename + ".vapi.hpp")

    logger = logging.getLogger("vppapigen.vapi")

    # Both emitters need a Parser registry. The C and C++ paths build the
    # registry independently because the C++ path needs CppMessage instances
    # for the template-helper methods.
    c_parser = parser_from_ast(s, apifilename, logger)
    with open(h_filename, "w") as fd:
        write_vapi_h(c_parser, apifilename, basename + ".vapi.h", fd)

    cpp_parser = parser_from_ast_cpp(s, apifilename, logger)
    with open(hpp_filename, "w") as fd:
        write_vapi_hpp(cpp_parser, apifilename, fd, gen_h_prefix="vapi/")

    return ""
