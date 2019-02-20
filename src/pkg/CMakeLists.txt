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

foreach(f rules changelog)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/debian/${f}.in
    ${CMAKE_BINARY_DIR}/debian/${f}
  )
endforeach()

foreach(f control copyright vpp.preinst vpp.postrm vpp.postinst vpp.service)
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
