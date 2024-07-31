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

option(VPP_FIPS_CRYPTO_NATIVE
 "FIPS-ready crypto native plugin"
 OFF
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  list(APPEND VARIANTS "slm\;-march=silvermont -maes")
  list(APPEND VARIANTS "hsw\;-march=haswell -maes")
  if(compiler_flag_march_skylake_avx512 AND compiler_flag_mprefer_vector_width_256)
    list(APPEND VARIANTS "skx\;-march=skylake-avx512 -mprefer-vector-width=256")
  endif()
  if(compiler_flag_march_icelake_client AND compiler_flag_mprefer_vector_width_512)
    list(APPEND VARIANTS "icl\;-march=icelake-client -mprefer-vector-width=512")
  endif()
  if(compiler_flag_march_alderlake)
    list(APPEND VARIANTS "adl\;-march=alderlake -mprefer-vector-width=256")
  endif()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  list(APPEND VARIANTS "armv8\;-march=armv8.1-a+crc+crypto")
endif()

set (COMPILE_FILES aes_cbc.c aes_gcm.c aes_ctr.c sha2.c)
set (COMPILE_FILES_EXTERNAL aes_gcm_external.c aes_ctr_external.c)
set (COMPILE_OPTS -Wall -fno-common)

if (${VPP_FIPS_CRYPTO_NATIVE})
  set (COMPILE_OPTS ${COMPILE_OPTS} -DCRYPTO_NATIVE_EXTERNAL)
endif()

if (NOT VARIANTS)
  return()
endif()

add_vpp_plugin(crypto_native SOURCES main.c)

foreach(VARIANT ${VARIANTS})
  list(GET VARIANT 0 v)
  list(GET VARIANT 1 f)
  set(l crypto_native_${v})
  if (${VPP_FIPS_CRYPTO_NATIVE})
    set (REWRITE_OPTS
      -Daes_gcm_internal=aes_gcm_internal_${v}
      -Dclib_aes_gcm_key_expand_internal=clib_aes_gcm_key_expand_internal_${v}
      -Dclib_aes_ctr_init_internal=clib_aes_ctr_init_internal_${v}
      -Dclib_aes_ctr_transform_internal=clib_aes_ctr_transform_internal_${v}
      -Dclib_aes_ctr_key_expand_internal=clib_aes_ctr_key_expand_internal_${v}
    )
  endif()
  add_library(${l} OBJECT ${COMPILE_FILES})
  set_target_properties(${l} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  separate_arguments(f)
  target_compile_options(${l} PUBLIC ${f} ${COMPILE_OPTS} ${REWRITE_OPTS})
  target_sources(crypto_native_plugin PRIVATE $<TARGET_OBJECTS:${l}>)

  if (${VPP_FIPS_CRYPTO_NATIVE})
    set(l2 crypto_native_external_${v})
    add_library(${l2} OBJECT ${COMPILE_FILES_EXTERNAL})
    set_target_properties(${l2} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(${l2} PUBLIC ${f} ${COMPILE_OPTS} ${REWRITE_OPTS})
    target_sources(crypto_native_plugin PRIVATE $<TARGET_OBJECTS:${l2}>)
  endif()
endforeach()
