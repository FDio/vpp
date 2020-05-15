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

option(VPP_BUILD_G2 "Build g2 tool." OFF)
if(VPP_BUILD_G2)
  find_package(GTK2 COMPONENTS gtk)
  if(GTK2_FOUND)
    set(CMAKE_C_FLAGS "-Wno-deprecated-declarations ${CMAKE_C_FLAGS}")
    include_directories(${GTK2_INCLUDE_DIRS})
    add_vpp_executable(g2
      SOURCES
      clib.c
      cpel.c
      events.c
      main.c
      menu1.c
      pointsel.c
      props.c
      g2version.c
      view1.c

      LINK_LIBRARIES vppinfra Threads::Threads m ${GTK2_LIBRARIES}
    )
  endif()
endif()
