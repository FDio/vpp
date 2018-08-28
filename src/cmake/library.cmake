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

macro(add_vpp_library lib)
  cmake_parse_arguments(ARG
    ""
    ""
    "SOURCES;MULTIARCH_SOURCES;API_FILES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS"
    ${ARGN}
  )

  add_library(${lib} SHARED ${ARG_SOURCES})
  target_compile_options(${lib} PRIVATE -Wall)

  # library deps
  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${lib} ${ARG_LINK_LIBRARIES})
  endif()
  # install .so
  install(TARGETS ${lib} DESTINATION ${VPP_LIB_DIR_NAME})

  if(ARG_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${lib} ${ARG_MULTIARCH_SOURCES})
  endif()

  if(ARG_API_FILES)
    vpp_add_api_files(${lib} ${ARG_API_FILES})
    foreach(file ${ARG_API_FILES})
      get_filename_component(dir ${file} DIRECTORY)
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}.h DESTINATION include/${lib}/${dir})
    endforeach()
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${lib} ${ARG_DEPENDS})
  endif()

  # install headers
  if(ARG_INSTALL_HEADERS)
    foreach(file ${ARG_INSTALL_HEADERS})
      get_filename_component(dir ${file} DIRECTORY)
      install(FILES ${file} DESTINATION include/${lib}/${dir})
    endforeach()
  endif()
endmacro()

##############################################################################
# header files
##############################################################################
function (add_vpp_headers path)
  foreach(file ${ARGN})
    get_filename_component(dir ${file} DIRECTORY)
    install(FILES ${file} DESTINATION include/${path}/${dir})
  endforeach()
endfunction()
