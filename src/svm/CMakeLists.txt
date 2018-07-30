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

##############################################################################
# svm shared library
##############################################################################
add_library(svm SHARED
  svm.c
  ssvm.c
  svm_fifo.c
  svm_fifo_segment.c
  queue.c
  message_queue.c
)
target_link_libraries(svm vppinfra rt pthread)
install(TARGETS svm DESTINATION lib)

##############################################################################
# svmdb shared library
##############################################################################
add_library(svmdb SHARED svmdb.c)
target_link_libraries(svmdb svm vppinfra rt pthread)
install(TARGETS svmdb DESTINATION lib)

##############################################################################
# svm headers
##############################################################################
vpp_add_header_files(svm
  ssvm.h
  svm_common.h
  svmdb.h
  svm_fifo.h
  svm_fifo_segment.h
  queue.h
  message_queue.h
  svm.h
)

##############################################################################
# svm tools
##############################################################################

add_executable (svmtool svmtool.c)
target_link_libraries (svmtool vppinfra svm)
add_executable (svmdbtool svmdbtool.c)
target_link_libraries (svmdbtool vppinfra svm svmdb)

install(
  TARGETS svmtool svmdbtool
  DESTINATION bin
)

