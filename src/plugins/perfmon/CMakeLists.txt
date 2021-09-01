# Copyright (c) 2020 Cisco and/or its affiliates.
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

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*|aarch64.*")
  return()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  list(APPEND ARCH_PMU_SOURCES
    intel/dispatch_wrapper.c
    intel/core.c
    intel/uncore.c
    intel/bundle/inst_and_clock.c
    intel/bundle/load_blocks.c
    intel/bundle/mem_bw.c
    intel/bundle/cache_hit_miss.c
    intel/bundle/branch_mispred.c
    intel/bundle/power_license.c
    intel/bundle/topdown_metrics.c
  )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64.*")
  list(APPEND ARCH_PMU_SOURCES
    arm/dispatch_wrapper.c
    arm/events.c
    arm/bundle/inst_clock.c
    arm/bundle/cache_data.c
    arm/bundle/cache_inst.c
    arm/bundle/cache_data_tlb.c
    arm/bundle/cache_inst_tlb.c
    arm/bundle/mem_access.c
    arm/bundle/branch_pred.c
    arm/bundle/stall.c
  )
endif()

add_vpp_plugin(perfmon
  SOURCES
  cli.c
  linux.c
  perfmon.c
  table.c
  ${ARCH_PMU_SOURCES}
)