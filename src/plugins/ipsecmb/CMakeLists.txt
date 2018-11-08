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

find_path(IPSECMB_INCLUDE_DIR NAMES intel-ipsec-mb.h HINTS ${IPSECMB_INCLUDE_DIR_HINT})
find_library(IPSECMB_LIB NAMES libIPSec_MB.a HINTS ${IPSECMB_LIB_DIR_HINT})

if(IPSECMB_INCLUDE_DIR AND IPSECMB_LIB)

	get_filename_component(IPSECMB_LIB_DIR ${IPSECMB_LIB} DIRECTORY)
	set(IPSECMB_LINK_FLAGS "${IPSECMB_LINK_FLAGS} -L${IPSECMB_LIB_DIR} -Wl,--whole-archive ${IPSECMB_LIB} -Wl,--no-whole-archive")
	set(IPSECMB_LINK_FLAGS "${IPSECMB_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
	include_directories(${IPSECMB_INCLUDE_DIR})
	add_vpp_plugin(ipsecmb
		SOURCES
		ipsecmb.c
		ah_encrypt.c
		ah_decrypt.c
		esp_encrypt.c
		esp_decrypt.c

		MULTIARCH_SOURCES
		ah_encrypt.c
		ah_decrypt.c
		esp_encrypt.c
		esp_decrypt.c

		LINK_FLAGS
		${IPSECMB_LINK_FLAGS}
		)

	message(STATUS "Intel IPSecMB found: ${IPSECMB_INCLUDE_DIR}")
else()
	message(STATUS "Intel IPSecMB not found")
endif()


