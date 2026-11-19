# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
# Author: Damjan Marion

# python test suite targets (the work is done by src/cmake/test.py):
#   ninja test          run everything (TEST=<filter> in the environment selects)
#   ninja test-<name>   run test/test_<name>.py
#   ninja test-config   TUI to edit the saved options
# See the docstring of test.py for the options.
#
# They use the shared python environment of venv.cmake, with extras:
#   ninja venv-test     vpp_papi and the patched scapy
#   ninja venv-tui      textual, only needed by test-config

get_filename_component(_ws ${CMAKE_SOURCE_DIR}/.. ABSOLUTE)
set(_test_py ${CMAKE_CURRENT_LIST_DIR}/test.py)
set(_venv_py ${VPP_VENV_DIR}/bin/python3)

# vpp_papi from the source tree, and scapy with our patches on top. scapy is
# reinstalled first so that the patches always apply to pristine files.
file(STRINGS ${VPP_VENV_REQUIREMENTS} _scapy REGEX "^scapy==")
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" _scapy_version "${_scapy}")
set(_scapy_patch_dir ${_ws}/test/patches/scapy-${_scapy_version})
file(GLOB _scapy_patches CONFIGURE_DEPENDS ${_scapy_patch_dir}/*.patch)
execute_process(
  COMMAND ${VPP_PYTHON3} -c
    "import sys; print('%d.%d' % sys.version_info[:2], end='')"
  OUTPUT_VARIABLE _python_version
)
set(_papi_dir ${CMAKE_SOURCE_DIR}/vpp-api/python)
set(_test_stamp ${VPP_VENV_DIR}/.test.stamp)

add_custom_command(
  OUTPUT ${_test_stamp}
  COMMAND ${VPP_VENV_PIP_INSTALL} -e ${_papi_dir}
  COMMAND ${VPP_VENV_PIP_INSTALL} ${VPP_VENV_PIP_REINSTALL_FLAG} --no-deps
    scapy==${_scapy_version}
  COMMAND ${VPP_PYTHON3} ${_test_py} patch ${_scapy_patch_dir}
    ${VPP_VENV_DIR}/lib/python${_python_version}/site-packages
  COMMAND ${CMAKE_COMMAND} -E touch ${_test_stamp}
  DEPENDS ${VPP_VENV_STAMP} ${_scapy_patches} ${_papi_dir}/setup.py
  COMMENT "Adding the test packages to ${VPP_VENV_DIR}"
  USES_TERMINAL
  VERBATIM
)
add_custom_target(venv-test DEPENDS ${_test_stamp})

# not part of test/requirements-3.txt, which "make test" installs too
set(_tui_requirements ${CMAKE_CURRENT_LIST_DIR}/requirements-tui.txt)
set(_tui_stamp ${VPP_VENV_DIR}/.tui.stamp)

add_custom_command(
  OUTPUT ${_tui_stamp}
  COMMAND ${VPP_VENV_PIP_INSTALL} -r ${_tui_requirements}
  COMMAND ${CMAKE_COMMAND} -E touch ${_tui_stamp}
  DEPENDS ${VPP_VENV_STAMP} ${_tui_requirements}
  COMMENT "Adding the TUI packages to ${VPP_VENV_DIR}"
  USES_TERMINAL
  VERBATIM
)
add_custom_target(venv-tui DEPENDS ${_tui_stamp})

# Tests need what a plain "ninja" builds: plugins pull each other in at run
# time, and there are API test plugins and test binaries besides them. Collect
# every library and executable which is part of the "all" target.
function(vpp_collect_targets result dir)
  set(targets ${${result}})
  get_property(here DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
  foreach(t ${here})
    get_target_property(type ${t} TYPE)
    get_target_property(excluded ${t} EXCLUDE_FROM_ALL)
    if(type MATCHES "^(EXECUTABLE|(SHARED|STATIC|MODULE)_LIBRARY)$"
       AND NOT excluded)
      list(APPEND targets ${t})
    endif()
  endforeach()
  get_property(subdirs DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)
  foreach(d ${subdirs})
    vpp_collect_targets(targets ${d})
  endforeach()
  set(${result} ${targets} PARENT_SCOPE)
endfunction()

set(_vpp_test_deps venv-test)
vpp_collect_targets(_vpp_test_deps ${CMAKE_SOURCE_DIR})

set(_run ${VPP_PYTHON3} ${_test_py} run ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}
  ${VPP_VENV_DIR} ${VPP_LIBRARY_DIR})

add_custom_target(test
  COMMAND ${_run}
  DEPENDS ${_vpp_test_deps}
  COMMENT "Running VPP python tests..."
  USES_TERMINAL
)

add_custom_target(test-config
  COMMAND ${_venv_py} ${_test_py} config ${CMAKE_BINARY_DIR}
  DEPENDS venv-tui
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
