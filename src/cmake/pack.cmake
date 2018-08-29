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
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VPP Team")
set(CPACK_PACKAGE_NAME "vpp")
set(CPACK_PACKAGE_VENDOR "fd.io")
set(CPACK_PACKAGE_VERSION "18.10")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_IGNORE_GROUPS 1)

get_cmake_property(components COMPONENTS)
foreach(lc ${components})
  string(TOUPPER ${lc} uc)
  set(CPACK_DEBIAN_${uc}_PACKAGE_NAME "${lc}")
  set(CPACK_DEBIAN_${uc}_FILE_NAME "${lc}.deb")
endforeach()

include(CPack)
