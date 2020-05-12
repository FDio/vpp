# Copyright (c) 2019 Cisco and/or its affiliates.
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

get_cmake_property(VPP_COMPONENTS COMPONENTS)
string(REPLACE ";" " " VPP_COMPONENTS "${VPP_COMPONENTS}")

execute_process(
  COMMAND date -R
  OUTPUT_VARIABLE TIMESTAMP
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# parse /etc/os-release
file(READ "/etc/os-release" os_release)
string(REPLACE "\n" ";" os_release ${os_release})
foreach(l ${os_release})
  string(REPLACE "=" ";" l ${l})
  list(GET l 0 _name)
  list(GET l 1 _value)
  string(REPLACE "\"" "" _value ${_value})
  set(OS_${_name} ${_value})
endforeach()

if (OS_ID STREQUAL "ubuntu" AND OS_VERSION_ID VERSION_LESS 20.04)
  set(VPP_DEB_BUILD_DEPENDS "python-all, python3-all, python3-setuptools")
  set(VPP_DEB_WITH_PYTHON2 "yes")
else()
  set(VPP_DEB_BUILD_DEPENDS "python3-all, python3-setuptools")
  set(VPP_DEB_WITH_PYTHON2 "no")
endif()

foreach(f rules changelog control)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/debian/${f}.in
    ${CMAKE_BINARY_DIR}/debian/${f}
    @ONLY
  )
endforeach()

foreach(f copyright vpp.preinst vpp.postrm vpp.postinst vpp.service)
  file(COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/debian/${f}
    DESTINATION ${CMAKE_BINARY_DIR}/debian
  )
endforeach()

file(WRITE ${CMAKE_BINARY_DIR}/debian/compat "9\n")

add_custom_target(package-deb
  COMMENT "Building .deb packages..."
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  COMMAND "dpkg-buildpackage" "-us" "-uc" "-b"
  USES_TERMINAL
)
