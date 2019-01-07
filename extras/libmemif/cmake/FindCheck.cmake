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

########################################
#
# Find the Libcheck library and includes
# This module sets:
#  CHECK_FOUND:          True if Libcheck was found
#  CHECK_LIBRARY:        The Libcheck library
#  CHECK_INCLUDE_DIR:    The Libcheck include dir
#

set(CHECK_SEARCH_PATH_LIST
  ${CHECK_HOME}
  $ENV{CHECK_HOME}
  /usr/local
  /opt
  /usr
)

find_path(CHECK_INCLUDE_DIR check.h
  HINTS ${CHECK_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the check includes"
)

find_library(CHECK_LIBRARY NAMES check
  HINTS ${CHECK_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the check libraries"
)

execute_process(
  COMMAND grep "CHECK_MICRO_VERSION" ${CHECK_INCLUDE_DIR}/check.h
  COMMAND grep -Eo [0-9]+
  OUTPUT_VARIABLE CHECK_MICRO_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND grep "CHECK_MINOR_VERSION" ${CHECK_INCLUDE_DIR}/check.h
  COMMAND grep -Eo [0-9]+
  OUTPUT_VARIABLE CHECK_MINOR_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND grep "CHECK_MAJOR_VERSION" ${CHECK_INCLUDE_DIR}/check.h
  COMMAND grep -Eo [0-9]+
  OUTPUT_VARIABLE CHECK_MAJOR_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(CHECK_VERSION "${CHECK_MAJOR_VERSION}.${CHECK_MINOR_VERSION}.${CHECK_MICRO_VERSION}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Check
  REQUIRED_VARS CHECK_LIBRARY CHECK_INCLUDE_DIR
  VERSION_VAR CHECK_VERSION
)