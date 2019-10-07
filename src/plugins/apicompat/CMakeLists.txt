
# Copyright (c) <current-year> <your-organization>
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

add_vpp_plugin(apicompat
  SOURCES
  apicompat.c 
  apicompat.h

  foobar.c
  foobar.h
  foobar_upcall.h

  API_FILES
  apicompat.api

  INSTALL_HEADERS
  apicompat_all_api_h.h
  apicompat_msg_enum.h

  API_TEST_SOURCES
  apicompat_test.c
)


