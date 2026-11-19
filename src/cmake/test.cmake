# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
# Author: Damjan Marion

# python test suite targets (the work is done by src/cmake/test.py):
#   ninja test          run everything (TEST=<filter> in the environment selects)
#   ninja test-<name>   run test/test_<name>.py
#   ninja test-config   TUI to edit the saved options
# See the docstring of test.py for the options.

get_filename_component(_ws ${CMAKE_SOURCE_DIR}/.. ABSOLUTE)
set(_test_py ${CMAKE_CURRENT_LIST_DIR}/test.py)
if(NOT EXISTS ${_test_py})
  return()
endif()

set(_vpp_test_deps vpp)
foreach(name ${VPP_PLUGINS_LIST})
  if(TARGET ${name}_plugin)
    list(APPEND _vpp_test_deps ${name}_plugin)
  endif()
endforeach()
if(TARGET vpp_api_test)
  list(APPEND _vpp_test_deps vpp_api_test)
endif()

set(_run python3 ${_test_py} run ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${VPP_LIBRARY_DIR})

add_custom_target(test
  COMMAND ${_run}
  DEPENDS ${_vpp_test_deps}
  COMMENT "Running VPP python tests..."
  USES_TERMINAL
)

add_custom_target(test-config
  COMMAND python3 ${_test_py} config ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}
  COMMENT "Starting test options TUI..."
  USES_TERMINAL
)

file(GLOB _vpp_test_files ${_ws}/test/test_*.py)
foreach(f ${_vpp_test_files})
  get_filename_component(_n ${f} NAME_WE)
  string(REGEX REPLACE "^test_" "" _n ${_n})
  add_custom_target(test-${_n}
    COMMAND ${_run} ${_n}
    DEPENDS ${_vpp_test_deps}
    COMMENT "Running VPP python test ${_n}..."
    USES_TERMINAL
  )
endforeach()
