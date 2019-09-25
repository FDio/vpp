
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

add_vpp_plugin(ct6
  SOURCES
  ct6.c
  ct6_in2out.c
  ct6_out2in.c
  ct6.h

  MULTIARCH_SOURCES
  ct6_in2out.c
  ct6_out2in.c

  API_FILES
  ct6.api

  API_TEST_SOURCES
  ct6_test.c
)
