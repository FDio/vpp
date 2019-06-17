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
# Check for memfd_create headers and libs
##############################################################################
check_c_source_compiles("
  #define _GNU_SOURCE
  #include <sys/mman.h>
  int main() { return memfd_create (\"/dev/false\", 0); }
" HAVE_MEMFD_CREATE)

if (HAVE_MEMFD_CREATE)
    add_definitions(-DHAVE_MEMFD_CREATE)
endif()

check_c_source_compiles("
  #define _GNU_SOURCE
  #include <sched.h>
  int main() { return getcpu (0, 0); }
" HAVE_GETCPU)

if (HAVE_GETCPU)
    add_definitions(-DHAVE_GETCPU)
endif()

