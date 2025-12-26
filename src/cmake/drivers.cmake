# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

macro(add_vpp_driver name)
  cmake_parse_arguments(DRIVER
    ""
    "LINK_FLAGS;COMPONENT;DEV_COMPONENT;MULTIARCH_FORCE_ON"
    "SOURCES;LINK_LIBRARIES;SUPPORTED_OS_LIST;INCLUDE_DIRECTORIES;MULTIARCH_SOURCES"
    ${ARGN}
  )
  if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "")
    if(VPP_DRIVERS STREQUAL "none")
      return()
    endif()
    get_property(_vpp_drivers_filter GLOBAL PROPERTY VPP_DRIVERS_FILTER)
    list(FIND _vpp_drivers_filter ${name} _vpp_driver_idx)
    if(_vpp_driver_idx EQUAL -1)
      return()
    endif()
    list(REMOVE_AT _vpp_drivers_filter ${_vpp_driver_idx})
    set_property(GLOBAL PROPERTY VPP_DRIVERS_FILTER "${_vpp_drivers_filter}")
  endif()
  if (DRIVER_SUPPORTED_OS_LIST AND NOT ${CMAKE_SYSTEM_NAME} IN_LIST DRIVER_SUPPORTED_OS_LIST)
    message(WARNING "unsupported OS - ${name} driver disabled")
    return()
  endif()
  set(driver_name ${name}_driver)
  if(NOT DRIVER_COMPONENT)
    set(DRIVER_COMPONENT vpp-drivers)
  endif()
  if(NOT DRIVER_DEV_COMPONENT)
    if(NOT VPP_EXTERNAL_PROJECT)
      set(DRIVER_DEV_COMPONENT vpp-dev)
    else()
      set(DRIVER_DEV_COMPONENT ${DRIVER_COMPONENT}-dev)
    endif()
  endif()

  add_library(${driver_name} SHARED ${DRIVER_SOURCES})
  target_include_directories(${driver_name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  if(DRIVER_INCLUDE_DIRECTORIES)
    target_include_directories(${driver_name} PRIVATE ${DRIVER_INCLUDE_DIRECTORIES})
  endif()
  target_compile_options(${driver_name} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
  set_target_properties(${driver_name} PROPERTIES NO_SONAME 1)
  target_compile_options(${driver_name} PRIVATE "-fvisibility=hidden")
  target_compile_options (${driver_name} PRIVATE "-ffunction-sections")
  target_compile_options (${driver_name} PRIVATE "-fdata-sections")
  target_link_libraries (${driver_name} "-Wl,--gc-sections")
  set(deps "")
  if(NOT VPP_EXTERNAL_PROJECT)
    list(APPEND deps vpp_version_h)
  endif()
  if(deps)
    add_dependencies(${driver_name} ${deps})
  endif()
  set_target_properties(${driver_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_drivers)
  if(DRIVER_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${driver_name}
      SOURCES ${DRIVER_MULTIARCH_SOURCES}
      DEPENDS ${deps}
      FORCE_ON ${DRIVER_MULTIARCH_FORCE_ON}
      INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${DRIVER_INCLUDE_DIRECTORIES}
    )
  endif()
  if(DRIVER_LINK_LIBRARIES)
    target_link_libraries(${driver_name} ${DRIVER_LINK_LIBRARIES})
  endif()
  if(DRIVER_LINK_FLAGS)
    set_target_properties(${driver_name} PROPERTIES LINK_FLAGS "${DRIVER_LINK_FLAGS}")
  endif()

  set_property(GLOBAL APPEND PROPERTY VPP_DRIVERS_LIST ${name})

  install(
    TARGETS ${driver_name}
    DESTINATION ${VPP_LIBRARY_DIR}/vpp_drivers
    COMPONENT ${DRIVER_COMPONENT}
  )
endmacro()

macro(vpp_driver_find_library n var name)
  find_library(${var} NAMES ${name} ${ARGN})
  mark_as_advanced(${var})
if (NOT ${var})
  message(WARNING "-- ${name} library not found - ${n} driver disabled")
  return()
endif()
    message(STATUS "${n} driver needs ${name} library - found at ${${var}}")
endmacro()
