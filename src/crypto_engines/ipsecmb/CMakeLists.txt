
# Copyright (c) 2019 Cisco Systems
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

vpp_find_path(IPSECMB_INCLUDE_DIR NAMES intel-ipsec-mb.h HINTS ${IPSECMB_INCLUDE_DIR_HINT})
vpp_find_library(IPSECMB_LIB NAMES libIPSec_MB.a HINTS ${IPSECMB_LIB_DIR_HINT})

if(IPSECMB_INCLUDE_DIR AND IPSECMB_LIB)

	get_filename_component(IPSECMB_LIB_DIR ${IPSECMB_LIB} DIRECTORY)
	set(IPSECMB_LINK_FLAGS "${IPSECMB_LINK_FLAGS} -L${IPSECMB_LIB_DIR} -Wl,--whole-archive ${IPSECMB_LIB} -Wl,--no-whole-archive")
	set(IPSECMB_LINK_FLAGS "${IPSECMB_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
	include_directories(${IPSECMB_INCLUDE_DIR})
	add_vpp_crypto_engine(ipsecmb
		SOURCES
		ipsecmb.c

		LINK_FLAGS
		${IPSECMB_LINK_FLAGS}
		)

	# Get library version and verify it matches header
	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/ipsecmb_version.c "
		#include <stdio.h>
		#include \"${IPSECMB_INCLUDE_DIR}/intel-ipsec-mb.h\"
		int main(void) {
			if (IMB_VERSION_NUM != imb_get_version()) return 1;
			printf(\"%s\", IMB_VERSION_STR);
			return 0;
		}
	")
	try_run(IPSECMB_RUN_RESULT IPSECMB_COMPILE_RESULT
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/ipsecmb_version.c
		LINK_LIBRARIES ${IPSECMB_LIB}
		COMPILE_OUTPUT_VARIABLE IPSECMB_COMPILE_OUTPUT
		RUN_OUTPUT_VARIABLE IPSECMB_VERSION
	)
	if (NOT IPSECMB_COMPILE_RESULT)
		message(FATAL_ERROR "Intel IPSecMB version check failed to compile: ${IPSECMB_COMPILE_OUTPUT}")
	endif()
	if (NOT IPSECMB_RUN_RESULT EQUAL 0)
		message(FATAL_ERROR "Intel IPSecMB header version does not match library version")
	endif()

	if (${IPSECMB_VERSION} VERSION_GREATER "0.54.0")
		add_definitions(-DHAVE_IPSECMB_CHACHA_POLY)
	else()
		message(STATUS "Intel IPSecMB ${IPSECMB_VERSION} does not support chacha20-poly1305. Disabled")
	endif()

	target_compile_options(ipsecmb_crypto_engine PRIVATE "-march=silvermont" "-maes")
	message(STATUS "Intel IPSecMB found: ${IPSECMB_INCLUDE_DIR} (version ${IPSECMB_VERSION})")
else()
	message(STATUS "Intel IPSecMB not found")
endif()
