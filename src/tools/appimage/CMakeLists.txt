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
option(VPP_BUILD_APPIMAGE "Build VPP AppImage" OFF)
if(VPP_BUILD_APPIMAGE)
  install(FILES AppRun DESTINATION .
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_WRITE GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE)
  install(FILES vpp.desktop DESTINATION .)
  install(FILES vpp.png DESTINATION .)
  install(FILES vpp.svg DESTINATION share/icons/hicolor/scalable/vpp.svg)
  install(CODE "EXECUTE_PROCESS(COMMAND ln -s . ./usr
                WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX})")
  install(CODE "EXECUTE_PROCESS(
          COMMAND linuxdeploy --appdir vpp --output appimage
          WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/..)")
endif()
