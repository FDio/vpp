# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

##############################################################################
# Python virtual environment shared by the python based build targets
#   ninja venv  - create <build-root>/.venv with the packages from
#                 test/requirements-3.txt (docs, tests, ...)
#
# The environment is created at build time, never at configure time, and only
# again when the requirements file changes. Targets which need it depend on the
# "venv" target and use VPP_VENV_DIR.
##############################################################################
set(VPP_VENV_DIR ${CMAKE_BINARY_DIR}/.venv)
set(VPP_VENV_REQUIREMENTS ${CMAKE_SOURCE_DIR}/../test/requirements-3.txt)
set(VPP_VENV_STAMP ${VPP_VENV_DIR}/.requirements.stamp)

# pip and pip-tools versions are defined by the test makefile
file(STRINGS ${CMAKE_SOURCE_DIR}/../test/Makefile _venv_pins
  REGEX "^PIP(_TOOLS)?_VERSION=")
foreach(_pin ${_venv_pins})
  if(_pin MATCHES "^PIP_VERSION=(.+)$")
    set(VPP_VENV_PIP_VERSION ${CMAKE_MATCH_1})
  elseif(_pin MATCHES "^PIP_TOOLS_VERSION=(.+)$")
    set(VPP_VENV_PIP_TOOLS_VERSION ${CMAKE_MATCH_1})
  endif()
endforeach()

find_program(VPP_PYTHON3 python3 REQUIRED)
set(_venv_py ${VPP_VENV_DIR}/bin/python3)

add_custom_command(
  OUTPUT ${VPP_VENV_STAMP}
  COMMAND ${VPP_PYTHON3} -m venv ${VPP_VENV_DIR}
  COMMAND ${_venv_py} -m pip install pip==${VPP_VENV_PIP_VERSION}
  COMMAND ${_venv_py} -m pip install pip-tools==${VPP_VENV_PIP_TOOLS_VERSION}
  COMMAND ${_venv_py} -m pip install -r ${VPP_VENV_REQUIREMENTS}
  COMMAND ${CMAKE_COMMAND} -E touch ${VPP_VENV_STAMP}
  DEPENDS ${VPP_VENV_REQUIREMENTS}
  COMMENT "Creating python virtual environment in ${VPP_VENV_DIR}"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(venv DEPENDS ${VPP_VENV_STAMP})
