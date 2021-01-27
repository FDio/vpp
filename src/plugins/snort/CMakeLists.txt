# Copyright (c) 2021 Cisco and/or its affiliates.
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

add_vpp_plugin(snort
  SOURCES
  main.c
)

# DAQ

add_library(daq_vpp SHARED daq_vpp.c)
set_target_properties(daq_vpp PROPERTIES SOVERSION ${VPP_LIB_VERSION})
target_compile_options (daq_vpp PRIVATE "-fvisibility=hidden")
target_compile_options (daq_vpp PRIVATE "-DHAVE_VISIBILITY")
target_compile_options (daq_vpp PRIVATE "-I/opt/vpp/external/x86_64/include/")
install(TARGETS daq_vpp DESTINATION ${VPP_LIBRARY_DIR}/daq COMPONENT vpp-plugin-core)

add_library(daq_afpacket SHARED daq_afpacket.c)
set_target_properties(daq_afpacket PROPERTIES SOVERSION ${VPP_LIB_VERSION})
target_compile_options (daq_afpacket PRIVATE "-fvisibility=hidden")
target_compile_options (daq_afpacket PRIVATE "-DHAVE_VISIBILITY")
target_compile_options (daq_afpacket PRIVATE "-I/opt/vpp/external/x86_64/include/")
install(TARGETS daq_afpacket DESTINATION ${VPP_LIBRARY_DIR}/daq COMPONENT vpp-plugin-core)

