# Copyright (c) 2019 Tetsuya Murakami, Satoru Matsushima, Filip Varga.
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

add_vpp_plugin(srv6mobile
  SOURCES
  gtp4_e.c
  gtp6_e.c
  gtp6_d.c
  gtp6_d_di.c
  node.c

  INSTALL_HEADERS
  mobile.h
)
