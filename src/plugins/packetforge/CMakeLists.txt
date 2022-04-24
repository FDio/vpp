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

SET(USR_INCLUDE_PATH "/usr/include/")

vpp_find_path(PYTHON_INCLUDE_PATH NAMES Python.h PATHS ${USR_INCLUDE_PATH}*)

if(NOT PYTHON_INCLUDE_PATH)
  message(WARNING "Python.h not found - packetforge plugin disabled")
  return()
endif()

include_directories(${PYTHON_INCLUDE_PATH})
string(REPLACE ${USR_INCLUDE_PATH} "" PYTHON_LIB ${PYTHON_INCLUDE_PATH})

add_vpp_plugin(packetforge
  SOURCES
  packetforge.c

  LINK_LIBRARIES ${PYTHON_LIB}

  COMPONENT vpp-plugin-packetforge
)
