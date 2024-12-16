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

macro(add_vpp_crypto_engine name)
  cmake_parse_arguments(CRYPTO_ENGINE
    ""
    "LINK_FLAGS;COMPONENT;DEV_COMPONENT"
    "SOURCES;LINK_LIBRARIES;SUPPORTED_OS_LIST"
    ${ARGN}
  )
  if (CRYPTO_ENGINE_SUPPORTED_OS_LIST AND NOT ${CMAKE_SYSTEM_NAME} IN_LIST CRYPTO_ENGINE_SUPPORTED_OS_LIST)
    message(WARNING "unsupported OS - ${name} crypto engine disabled")
    return()
  endif()
  set(crypto_engine_name ${name}_crypto_engine)
  if(NOT CRYPTO_ENGINE_COMPONENT)
    set(CRYPTO_ENGINE_COMPONENT vpp-crypto-engines)
  endif()
  if(NOT CRYPTO_ENGINE_DEV_COMPONENT)
    if(NOT VPP_EXTERNAL_PROJECT)
      set(CRYPTO_ENGINE_DEV_COMPONENT vpp-dev)
    else()
      set(CRYPTO_ENGINE_DEV_COMPONENT ${CRYPTO_ENGINE_COMPONENT}-dev)
    endif()
  endif()

  add_library(${crypto_engine_name} SHARED ${CRYPTO_ENGINE_SOURCES})
  target_compile_options(${crypto_engine_name} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
  set_target_properties(${crypto_engine_name} PROPERTIES NO_SONAME 1)
  target_compile_options(${crypto_engine_name} PRIVATE "-fvisibility=hidden")
  target_compile_options (${crypto_engine_name} PRIVATE "-ffunction-sections")
  target_compile_options (${crypto_engine_name} PRIVATE "-fdata-sections")
  target_link_libraries (${crypto_engine_name} "-Wl,--gc-sections")
  set(deps "")
  if(NOT VPP_EXTERNAL_PROJECT)
    list(APPEND deps vpp_version_h)
  endif()
  if(deps)
    add_dependencies(${crypto_engine_name} ${deps})
  endif()
  set_target_properties(${crypto_engine_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_crypto_engines)
  if(CRYPTO_ENGINE_LINK_LIBRARIES)
    target_link_libraries(${crypto_engine_name} ${CRYPTO_ENGINE_LINK_LIBRARIES})
  endif()
  if(CRYPTO_ENGINE_LINK_FLAGS)
    set_target_properties(${crypto_engine_name} PROPERTIES LINK_FLAGS "${CRYPTO_ENGINE_LINK_FLAGS}")
  endif()

  install(
    TARGETS ${crypto_engine_name}
    DESTINATION ${VPP_LIBRARY_DIR}/vpp_crypto_engines
    COMPONENT ${CRYPTO_ENGINE_COMPONENT}
  )
endmacro()

macro(vpp_crypto_engine_find_library n var name)
  find_library(${var} NAMES ${name} ${ARGN})
  mark_as_advanced(${var})
if (NOT ${var})
  message(WARNING "-- ${name} library not found - ${n} crypto engine disabled")
  return()
endif()
    message(STATUS "${n} crypto engine needs ${name} library - found at ${${var}}")
endmacro()
