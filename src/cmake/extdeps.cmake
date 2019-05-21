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

function(check_ext_dep_version name version)
  set(VERSION_FILE
    /opt/vpp/external/${CMAKE_HOST_SYSTEM_PROCESSOR}/share/${name}_version
  )
  if(EXISTS ${VERSION_FILE})
    file(STRINGS ${VERSION_FILE} INSTALLED_VERSION LIMIT_COUNT 1)
  else()
    set(INSTALLED_VERSION "unknown")
  endif()
  if(NOT ${INSTALLED_VERSION} STREQUAL ${version})
    message(WARNING "Wrong ${name} version - the build may fail")
    message(WARNING "Run 'make install-ext-deps' to fix.")
  endif()
endfunction()
