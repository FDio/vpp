# Copyright (c) 2026 Moinak Bhattacharyya <moinakb001@gmail.com>
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

vpp_find_path(URING_INCLUDE_DIR NAMES liburing.h)
if (NOT URING_INCLUDE_DIR)
  message(WARNING "liburing headers not found - iouring plugin disabled")
  return()
endif()

set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
vpp_plugin_find_library(iouring URING_LIB liburing.so)
if (NOT URING_LIB)
  message(WARNING "iouring plugin - missing liburing")
  return()
endif()

include_directories(${URING_INCLUDE_DIR})

add_vpp_plugin(iouring
  SOURCES
  iouring_input.c
  iouring_test.c

  API_FILES

  INSTALL_HEADERS
  iouring_input.h

  LINK_LIBRARIES
  ${URING_LIB}

  API_TEST_SOURCES

)