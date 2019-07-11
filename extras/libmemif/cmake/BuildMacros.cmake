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

##############################
# Useful macro for building libraries
#

include(GNUInstallDirs)

macro(build_library lib)
  cmake_parse_arguments(ARG
    "SHARED;STATIC;"
    "COMPONENT;"
    "SOURCES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS;INCLUDE_DIRS;DEFINITIONS;"
    ${ARGN}
  )

  if (ARG_SHARED)
    list(APPEND TARGET_LIBS
      ${lib}
    )
    add_library(${lib} SHARED ${ARG_SOURCES})
  endif()

  if(ARG_STATIC)
    list(APPEND TARGET_LIBS
      ${lib}.static
    )
    add_library(${lib}.static STATIC ${ARG_SOURCES})
  endif()

  foreach(library ${TARGET_LIBS})
    # library deps
    if(ARG_LINK_LIBRARIES)
      target_link_libraries(${library} ${ARG_LINK_LIBRARIES})
    endif()

    if(ARG_DEFINITIONS)
      target_compile_definitions(${library} PRIVATE ${ARG_DEFINITIONS})
    endif()

    if(ARG_INCLUDE_DIRS)
      target_include_directories(${library} BEFORE PUBLIC
        ${ARG_INCLUDE_DIRS}
        ${PROJECT_BINARY_DIR}
      )
    endif()

    install(
      TARGETS ${library}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      COMPONENT ${ARG_COMPONENT}
    )

    if(ARG_DEPENDS)
      add_dependencies(${library} ${ARG_DEPENDS})
    endif()
  endforeach()

  if(ARG_INSTALL_HEADERS)
    foreach(file ${ARG_INSTALL_HEADERS})
      get_filename_component(dir ${file} DIRECTORY)
      install(
        FILES ${file}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${lib}/${dir}
        COMPONENT ${ARG_COMPONENT}-dev
      )
    endforeach()
  endif()
endmacro()
