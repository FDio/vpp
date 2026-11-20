# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

##############################################################################
# Sphinx documentation
#   ninja docs        - build HTML docs into <build-root>/.docs-build/html and
#                       fail on spelling errors
#   ninja docs-serve  - build docs and serve them over HTTP
#
# The python environment (sphinx, ...) is the shared <build-root>/.venv created
# by the "venv" target, see venv.cmake.
#
# What gets built (sources, siphon inputs, generated files...) is described by
# docs/docs.json, shared with the make based docs build.
##############################################################################
set(VPP_DOCS_PY ${CMAKE_SOURCE_DIR}/../docs/docs.py)
set(VPP_DOCS_OUT_DIR ${CMAKE_BINARY_DIR}/.docs-build)
set(VPP_DOCS_SERVE_ADDR "" CACHE STRING
  "Address docs-serve binds to (empty = all interfaces)")
set(VPP_DOCS_SERVE_PORT "8000" CACHE STRING "Port docs-serve listens on")

add_custom_target(docs
  COMMAND ${VPP_VENV_DIR}/bin/python3 ${VPP_DOCS_PY} build
    --out-dir ${VPP_DOCS_OUT_DIR} --venv ${VPP_VENV_DIR}
  COMMENT "Building documentation in ${VPP_DOCS_OUT_DIR}/html"
  USES_TERMINAL
  VERBATIM
)

add_dependencies(docs venv)

add_custom_target(docs-serve
  COMMAND python3 ${VPP_DOCS_PY} serve --out-dir ${VPP_DOCS_OUT_DIR}
    --port ${VPP_DOCS_SERVE_PORT} --addr "${VPP_DOCS_SERVE_ADDR}"
  DEPENDS docs
  USES_TERMINAL
  VERBATIM
)
