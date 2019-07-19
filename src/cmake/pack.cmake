# Copyright (c) 2018 Cisco and/or its affiliates.
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

# cmake_parse_arguments used to be a module and is now built-in since 3.4
if (CMAKE_VERSION VERSION_LESS "3.4")
include(CmakeParseArguments)
endif()

# name, vendor, description are maccros, arguments are in ${ARGN}
macro(add_vpp_packaging)
  cmake_parse_arguments(ARG
    ""
    "NAME;DESCRIPTION;VENDOR;VERSION"
    ""
    ${ARGN}
  )

  # parse /etc/os-release
  file(READ "/etc/os-release" os_version)
  string(REPLACE "\n" ";" os_version ${os_version})
  foreach(_ver ${os_version})
    string(REPLACE "=" ";" _ver ${_ver})
    list(GET _ver 0 _name)
    list(GET _ver 1 _value)
    set(OS_${_name} ${_value})
  endforeach()

  if ("${ARG_VERSION}" STREQUAL "")
      message(FATAL_ERROR "VPP version unset in add_vpp_packaging")
  endif()
  message(STATUS "VPP version:" ${ARG_VERSION})

  set(deb_ver "${ARG_VERSION}")
  set(rpm_ver "${ARG_VERSION}")

  set(CPACK_PACKAGE_NAME ${ARG_NAME})
  set(CPACK_STRIP_FILES OFF)
  set(CPACK_PACKAGE_VENDOR "${ARG_VENDOR}")
  set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
  set(CPACK_${CPACK_GENERATOR}_COMPONENT_INSTALL ON)
  set(CPACK_${type}_PACKAGE_DESCRIPTION "${ARG_DESCRIPTION}")
  set(CPACK_${type}_PACKAGE_RELEASE 1)

  if(OS_ID_LIKE MATCHES "debian")
    set(CPACK_GENERATOR "DEB")
    set(type "DEBIAN")
    set(CPACK_PACKAGE_VERSION "${deb_ver}")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VPP Team")
    execute_process(
      COMMAND dpkg --print-architecture
      OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    #CPACK_DEBIAN_FILE_NAME in cmake >= 3.6
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE})
  elseif(OS_ID_LIKE MATCHES "rhel")
    set(CPACK_GENERATOR "RPM")
    set(type "RPM")
    set(CPACK_PACKAGE_VERSION "${rpm_ver}")
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE CPACK_RPM_PACKAGE_ARCHITECTURE
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    #CPACK_DEBIAN_FILE_NAME in cmake >= 3.6
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}.${CPACK_RPM_PACKAGE_ARCHITECTURE})
  endif()

  if(CPACK_GENERATOR)
    include(CPack)
  else()
    message(ERROR "CPACK_GENERATOR must be set")
  endif()

endmacro()
