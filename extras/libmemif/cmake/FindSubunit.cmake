# Copyright (c) 2018-2019 Cisco and/or its affiliates.
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
# Find the Libsubunit library and includes
# This module sets:
#  SUBUNIT_FOUND:          True if Libsubunit was found
#  SUBUNIT_LIBRARY:        The Libsubunit library
#  SUBUNIT_INCLUDE_DIR:    The Libsubunit include dir
#

set(SUBUNIT_SEARCH_PATH_LIST
  ${SUBUNIT_HOME}
  $ENV{SUBUNIT_HOME}
  /usr/local
  /opt
  /usr
)

find_path(SUBUNIT_INCLUDE_DIR
  NAMES child.h
  HINTS ${SUBUNIT_SEARCH_PATH_LIST}
  PATH_SUFFIXES include subunit
)

find_library(SUBUNIT_LIBRARY
  NAMES subunit
  PATH_SUFFIXES lib
  HINTS ${SUBUNIT_SEARCH_PATH_LIST}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Subunit
  REQUIRED_VARS SUBUNIT_LIBRARY SUBUNIT_INCLUDE_DIR
)