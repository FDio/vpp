# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

if(NOT VPP_PLATFORM_USES_KDI)
  return()
endif()

set(VPP_KDI_KERNEL_DIR "" CACHE PATH "Kernel build directory for KDI")
set(VPP_LINUX_KERNEL_CROSS_COMPILE "" CACHE STRING "Linux kernel cross-compiler prefix")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(kdi_kernel_build_dir ${VPP_KDI_KERNEL_DIR})

  find_program(VPP_KERNEL_MAKE_EXECUTABLE NAMES make gmake)
  if(NOT VPP_KERNEL_MAKE_EXECUTABLE)
    message(WARNING "-- KDI disabled - make not found")
    return()
  endif()

  if(NOT kdi_kernel_build_dir AND CMAKE_SYSTEM_PROCESSOR STREQUAL CMAKE_HOST_SYSTEM_PROCESSOR)
    execute_process(
      COMMAND uname -r
      OUTPUT_VARIABLE VPP_HOST_KERNEL_RELEASE
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(kdi_kernel_build_dir "/lib/modules/${VPP_HOST_KERNEL_RELEASE}/build")
  endif()

  if(NOT kdi_kernel_build_dir
      OR NOT EXISTS "${kdi_kernel_build_dir}/Makefile"
      OR NOT EXISTS "${kdi_kernel_build_dir}/include/config/auto.conf"
      OR NOT EXISTS "${kdi_kernel_build_dir}/Module.symvers")
    message(WARNING "-- KDI disabled - Linux kernel build headers or Module.symvers not found; set VPP_KDI_KERNEL_DIR")
    return()
  endif()

  if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL CMAKE_HOST_SYSTEM_PROCESSOR)
    if(NOT EXISTS "${kdi_kernel_build_dir}/scripts/basic/fixdep")
      message(WARNING "-- KDI disabled - kernel build tree lacks host Kbuild helpers")
      return()
    endif()
    execute_process(
      COMMAND "${kdi_kernel_build_dir}/scripts/basic/fixdep"
      RESULT_VARIABLE kdi_fixdep_status
      ERROR_VARIABLE kdi_fixdep_error
      OUTPUT_QUIET
    )
    if(NOT "${kdi_fixdep_status}" MATCHES "^-?[0-9]+$"
        OR kdi_fixdep_error MATCHES "Could not open|Exec format error|error while loading shared libraries")
      message(WARNING "-- KDI disabled - kernel build tree has Kbuild helpers that cannot run on this host; use the configured kernel source/build directory")
      return()
    endif()
  endif()

  set(kdi_cross_compile ${VPP_LINUX_KERNEL_CROSS_COMPILE})
  if(NOT kdi_cross_compile AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL CMAKE_HOST_SYSTEM_PROCESSOR)
    file(STRINGS "${kdi_kernel_build_dir}/include/config/auto.conf"
      kdi_kernel_compiler_line REGEX "^CONFIG_CC_VERSION_TEXT=")
    string(REGEX REPLACE "^CONFIG_CC_VERSION_TEXT=\"?([^ \" ]+).*$" "\\1"
      kdi_kernel_compiler "${kdi_kernel_compiler_line}")
    if(kdi_kernel_compiler MATCHES "^(.*-)gcc$")
      set(kdi_cross_compile ${CMAKE_MATCH_1})
      find_program(kdi_kernel_compiler_path NAMES ${kdi_kernel_compiler})
      if(NOT kdi_kernel_compiler_path)
        message(WARNING "-- KDI disabled - kernel compiler '${kdi_kernel_compiler}' not found")
        return()
      endif()
    else()
      message(WARNING "-- KDI disabled - cannot infer the kernel cross-compiler from CONFIG_CC_VERSION_TEXT; set VPP_LINUX_KERNEL_CROSS_COMPILE")
      return()
    endif()
  endif()

  if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/linux/Makefile)
    message(FATAL_ERROR "No Linux backend for KDI")
  endif()

  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AARCH64).*")
    set(VPP_LINUX_KERNEL_ARCH arm64)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64).*")
    set(VPP_LINUX_KERNEL_ARCH x86)
  endif()

  set(kdi_output_dir ${CMAKE_BINARY_DIR}/kdi)
  set(kdi_make_args MO=${kdi_output_dir} KDIR=${kdi_kernel_build_dir})
  if(VPP_LINUX_KERNEL_ARCH)
    list(APPEND kdi_make_args ARCH=${VPP_LINUX_KERNEL_ARCH})
  endif()
  if(kdi_cross_compile)
    list(APPEND kdi_make_args CROSS_COMPILE=${kdi_cross_compile})
  endif()

  add_custom_target(kdi ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${kdi_output_dir}
    COMMAND ${VPP_KERNEL_MAKE_EXECUTABLE} -C ${CMAKE_CURRENT_SOURCE_DIR}/linux ${kdi_make_args}
    BYPRODUCTS ${kdi_output_dir}/vpp_kdi.ko
    USES_TERMINAL
    VERBATIM
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/freebsd/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/freebsd ${CMAKE_BINARY_DIR}/kdi/freebsd)
  else()
    message(WARNING "-- KDI disabled - FreeBSD backend is not available")
  endif()
else()
  message(WARNING "-- KDI disabled - no backend for ${CMAKE_SYSTEM_NAME}")
endif()
