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

message("-- Looking for Marvell musdk")
find_path(MUSDK_INCLUDE_DIR NAMES marvell/pp2/pp2.h)
find_library(MUSDK_LIB NAMES musdk)

if(MUSDK_INCLUDE_DIR AND MUSDK_LIB)
  add_vpp_plugin(marvell_plugin
    marvell.api
    plugin.c
    pp2/cli.c
    pp2/format.c
    pp2/input.c
    pp2/output.c
    pp2/pp2.c
  )
  include_directories(${MUSDK_INCLUDE_DIR})
  message("-- Looking for Marvell musdk - found")
else()
  message("-- Looking for Marvell musdk - not found - marvell_plugin disabled")
endif()
