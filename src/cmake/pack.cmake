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

##############################################################################
# DEB Packaging
##############################################################################

macro(add_vpp_packaging name)
  cmake_parse_arguments(ARG
    ""
    "NAME;DESCRIPION;VENDOR"
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

  execute_process(
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/../..
    COMMAND scripts/version
    OUTPUT_VARIABLE VPP_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  #define DEB and RPM version numbers
  set(deb_ver "${VPP_VERSION}")
  set(rpm_ver "${VPP_VERSION}")

  get_cmake_property(components COMPONENTS)

  if(OS_ID_LIKE MATCHES "debian")
    set(CPACK_GENERATOR "DEB")
    set(type "DEBIAN")
    set(CPACK_PACKAGE_VERSION "${deb_ver}")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VPP Team")
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
    foreach(lc ${components})
      string(TOUPPER ${lc} uc)
      set(CPACK_DEBIAN_${uc}_PACKAGE_NAME "${lc}")
    endforeach()
  elseif(OS_ID_LIKE MATCHES "rhel")
    set(CPACK_GENERATOR "RPM")
    set(type "RPM")
    set(CPACK_PACKAGE_VERSION "${rpm_ver}")
    set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
    foreach(lc ${components})
      string(TOUPPER ${lc} uc)
      if(${lc} MATCHES ".*-dev")
	set(CPACK_RPM_${uc}_DEBUGINFO_PACKAGE ON)
	set(lc ${lc}el)
      endif()
      set(CPACK_RPM_${uc}_PACKAGE_NAME "${lc}")
    endforeach()
  endif()

  if(CPACK_GENERATOR)
    set(CPACK_PACKAGE_NAME ${ARG_NAME})
    set(CPACK_STRIP_FILES OFF)
    set(CPACK_PACKAGE_VENDOR "${ARG_VENDOR}")
    set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
    set(CPACK_${CPACK_GENERATOR}_COMPONENT_INSTALL ON)
    set(CPACK_${type}_PACKAGE_DESCRIPTION "${ARG_DESCRIPTION}")
    set(CPACK_${type}_PACKAGE_RELEASE 1)
    include(CPack)
  endif()
endmacro()
