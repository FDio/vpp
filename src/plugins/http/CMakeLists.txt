# Copyright (c) 2022 Cisco and/or its affiliates.
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

option(VPP_ENABLE_HTTP_2 "Build http plugin with HTTP/2 enabled" OFF)
if(VPP_ENABLE_HTTP_2)
    add_compile_definitions(HTTP_2_ENABLE=1)
endif()

add_vpp_plugin(http
  SOURCES
  http2/hpack.c
  http2/http2.c
  http2/frame.c
  http.c
  http_buffer.c
  http_timer.c
  http1.c
)

add_vpp_plugin(http_unittest
  SOURCES
  test/http_test.c
)
