# Copyright (c) 2025 Internet Mastering & Company, Inc.
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

##############################################################################
# Arti Tor Client Plugin for VPP
##############################################################################

message(STATUS "Building Tor Client plugin")

##############################################################################
# Build Rust FFI library
##############################################################################

find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
  message(FATAL_ERROR "Cargo (Rust build tool) not found. Please install Rust.")
endif()

# Determine build profile
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CARGO_BUILD_TYPE "debug")
  set(CARGO_BUILD_FLAG "")
else()
  set(CARGO_BUILD_TYPE "release")
  set(CARGO_BUILD_FLAG "--release")
endif()

# Set Rust library path
set(ARTI_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/arti-ffi")
set(ARTI_FFI_TARGET_DIR "${ARTI_FFI_DIR}/target/${CARGO_BUILD_TYPE}")
set(ARTI_FFI_LIB "${ARTI_FFI_TARGET_DIR}/libarti_vpp_ffi.so")

# Custom command to build Rust library
add_custom_command(
  OUTPUT ${ARTI_FFI_LIB}
  COMMAND ${CARGO_EXECUTABLE} build ${CARGO_BUILD_FLAG}
  WORKING_DIRECTORY ${ARTI_FFI_DIR}
  DEPENDS
    ${ARTI_FFI_DIR}/Cargo.toml
    ${ARTI_FFI_DIR}/src/lib.rs
  COMMENT "Building Arti FFI library (Rust)"
)

# Create custom target for Rust library
add_custom_target(arti_ffi_build ALL DEPENDS ${ARTI_FFI_LIB})

##############################################################################
# Install Rust library
##############################################################################

install(
  FILES ${ARTI_FFI_LIB}
  DESTINATION ${VPP_LIBRARY_DIR}
  COMPONENT vpp-plugin-tor-client
)

##############################################################################
# VPP Plugin
##############################################################################

add_vpp_plugin(tor_client
  SOURCES
    tor_client.c
    tor_client_api.c
    tor_client_cli.c
    tor_socks5.c

  API_FILES
    tor_client.api

  LINK_LIBRARIES
    ${ARTI_FFI_LIB}

  INSTALL_HEADERS
    tor_client.h
)

# Add dependency to ensure Rust library is built first
add_dependencies(tor_client_plugin arti_ffi_build)

##############################################################################
# API test generation
##############################################################################

add_vpp_api_test_plugin(tor_client
  API_FILES
    tor_client.api
)
