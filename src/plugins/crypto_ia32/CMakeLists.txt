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

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  return()
endif()

add_vpp_plugin(crypto_ia32 SOURCES main.c)

list(APPEND VARIANTS "sse42\;-march=silvermont")
list(APPEND VARIANTS "avx2\;-march=core-avx2")
if(compiler_flag_march_skylake_avx512)
  list(APPEND VARIANTS "avx512\;-march=skylake-avx512")
endif()

foreach(VARIANT ${VARIANTS})
  list(GET VARIANT 0 v)
  list(GET VARIANT 1 f)
  set(l crypto_ia32_${v})
  add_library(${l} OBJECT aes_cbc.c aes_gcm.c)
  set_target_properties(${l} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_options(${l} PUBLIC ${f} -Wall -fno-common -maes)
  target_sources(crypto_ia32_plugin PRIVATE $<TARGET_OBJECTS:${l}>)
endforeach()
