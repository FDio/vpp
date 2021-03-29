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
add_custom_target(modified_lib_fuzzer
           COMMAND objcopy --redefine-sym main=fuzzer_lib_main /usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/libclang_rt.fuzzer-x86_64.a ${PROJECT_BINARY_DIR}/lib/modified_lib_fuzzer.a
)

macro(add_vpp_executable exec)
  cmake_parse_arguments(ARG
    "ENABLE_EXPORTS;NO_INSTALL"
    ""
    "SOURCES;LINK_LIBRARIES;DEPENDS"
    ${ARGN}
  )

  add_executable(${exec} ${ARG_SOURCES})
  if (VPP_ENABLE_FUZZER)
     if ("${CMAKE_EXE_LINKER_FLAGS}" MATCHES "fuzzer-no-link")
     else()
       set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=fuzzer-no-link ${PROJECT_BINARY_DIR}/plugins/fuzzer/CMakeFiles/fuzzer_plugin.dir/fuzzer_entry.c.o ${PROJECT_BINARY_DIR}/lib/modified_lib_fuzzer.a")
       add_dependencies(${exec} modified_lib_fuzzer)
       add_dependencies(${exec} fuzzer_plugin)
     endif()
  endif (VPP_ENABLE_FUZZER)


  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${exec} ${ARG_LINK_LIBRARIES})
  endif()
  if(ARG_ENABLE_EXPORTS)
    set_target_properties(${exec} PROPERTIES ENABLE_EXPORTS 1)
  endif()
  if(ARG_DEPENDS)
    add_dependencies(${exec} ${ARG_DEPENDS})
  endif()
  if(NOT ARG_NO_INSTALL)
    install(TARGETS ${exec} DESTINATION ${VPP_RUNTIME_DIR})
  endif()
endmacro()

