# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

##############################################################################
# Python virtual environment shared by the python based build targets
#   ninja venv  - create <build-root>/.venv with the packages from
#                 test/requirements-3.txt (docs, tests, ...)
#
# The environment is created at build time, never at configure time, and from
# scratch whenever the requirements file changes. uv is used when available,
# pip otherwise.
#
# Targets which need it depend on the "venv" target and use VPP_VENV_DIR.
# Those needing more than the common packages add their own stamp file inside
# VPP_VENV_DIR, which depends on VPP_VENV_STAMP and installs the extras with
# VPP_VENV_PIP_INSTALL (see test.cmake).
##############################################################################
set(VPP_VENV_DIR ${CMAKE_BINARY_DIR}/.venv)
set(VPP_VENV_REQUIREMENTS ${CMAKE_SOURCE_DIR}/../test/requirements-3.txt)
set(VPP_VENV_STAMP ${VPP_VENV_DIR}/.requirements.stamp)

find_program(VPP_PYTHON3 python3 REQUIRED)
find_program(VPP_UV uv)
set(_venv_py ${VPP_VENV_DIR}/bin/python3)

if(VPP_UV)
  set(VPP_VENV_PIP_INSTALL ${VPP_UV} pip install --python ${_venv_py})
  set(VPP_VENV_PIP_REINSTALL_FLAG --reinstall)
  set(_venv_create
    COMMAND ${VPP_UV} venv --python ${VPP_PYTHON3} ${VPP_VENV_DIR}
    COMMAND ${VPP_UV} pip sync --python ${_venv_py} ${VPP_VENV_REQUIREMENTS}
  )
else()
  # pip and pip-tools versions are defined by the test makefile
  file(STRINGS ${CMAKE_SOURCE_DIR}/../test/Makefile _venv_pins
    REGEX "^PIP(_TOOLS)?_VERSION=")
  foreach(_pin ${_venv_pins})
    if(_pin MATCHES "^PIP_VERSION=(.+)$")
      set(_pip_version ${CMAKE_MATCH_1})
    elseif(_pin MATCHES "^PIP_TOOLS_VERSION=(.+)$")
      set(_pip_tools_version ${CMAKE_MATCH_1})
    endif()
  endforeach()

  set(VPP_VENV_PIP_INSTALL ${_venv_py} -m pip install)
  set(VPP_VENV_PIP_REINSTALL_FLAG --force-reinstall)
  set(_venv_create
    COMMAND ${VPP_PYTHON3} -m venv ${VPP_VENV_DIR}
    COMMAND ${VPP_VENV_PIP_INSTALL} pip==${_pip_version}
    COMMAND ${VPP_VENV_PIP_INSTALL} pip-tools==${_pip_tools_version}
    COMMAND ${VPP_VENV_PIP_INSTALL} -r ${VPP_VENV_REQUIREMENTS}
  )
endif()

# the venv keeps itself out of git, not every tool creating it takes care of that
set(_venv_gitignore ${CMAKE_BINARY_DIR}/CMakeFiles/venv.gitignore)
file(WRITE ${_venv_gitignore} "*\n")

add_custom_command(
  OUTPUT ${VPP_VENV_STAMP}
  COMMAND ${CMAKE_COMMAND} -E rm -rf ${VPP_VENV_DIR}
  ${_venv_create}
  COMMAND ${CMAKE_COMMAND} -E copy ${_venv_gitignore}
    ${VPP_VENV_DIR}/.gitignore
  COMMAND ${CMAKE_COMMAND} -E touch ${VPP_VENV_STAMP}
  DEPENDS ${VPP_VENV_REQUIREMENTS}
  COMMENT "Creating python virtual environment in ${VPP_VENV_DIR}"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(venv DEPENDS ${VPP_VENV_STAMP})
