# Copyright (c) 2018 Cavium, Inc
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

AC_DEFUN([AX_READ_FILE_MACRO],
[
 AC_MSG_CHECKING([value for $1 against ($2,$3) in $4 ])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
    [[#include <$4>]],
    [[
        #if $1 != $2
            exit(1);
        #endif
    ]])],
    [VAL_$1=$2]
    [AC_MSG_RESULT([$2])],
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
        [[#include <$4>]],
        [[
            #if $1 != $3
                exit(1);
            #endif
        ]])],
        [VAL_$1=$3]
        [AC_MSG_RESULT([$3])],
        [VAL_$1="unset"]
        [AC_MSG_RESULT([unset])]
    )
  )
])

AC_DEFUN([AX_DPDK_DETECT_CACHELINE_SIZE],
[
 AX_READ_FILE_MACRO(RTE_CACHE_LINE_SIZE,64,128,rte_config.h)
 AC_MSG_CHECKING([for issubst/log2_cacheline_size])
 AS_CASE([$VAL_RTE_CACHE_LINE_SIZE],
         [128],[dpdk_defines_cacheline_size=yes; dpdk_log2_cacheline_size=7],
         #Set default for 64B
         [dpdk_defines_cacheline_size=yes;dpdk_log2_cacheline_size=6]
 )
 AC_MSG_RESULT([$dpdk_defines_cacheline_size/$dpdk_log2_cacheline_size])
])

AC_DEFUN([AX_READ_PROC_CPUINFO],
[
 AC_MSG_CHECKING([for /proc/cpuinfo for issubst/Impl/Part/log2_cacheline_size])
 m4_define([read_midr_impl],
           [`awk '/implementer/ {print $[]4;exit}' /proc/cpuinfo`])
 m4_define([read_midr_partnum],
           [`awk '/part/ {print $[]4;exit}' /proc/cpuinfo`])
 limpl=read_midr_impl()
 lpart=read_midr_partnum()
 AS_CASE([$limpl],
  [0x43], [AS_CASE([$lpart],
                   [0x0a1],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
                   [0x0a2],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
                   [0x0a3],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
                   [0x0b1],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
                   [0x0b2],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
                   # Set cache line size 64B for ThunderX2
                   [vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=6]
           )],
  #Set default cache line size to 64B
  [vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=6]
 )
 AC_MSG_RESULT([$vpp_defines_cacheline_size/$limpl/$lpart/$vpp_log2_cacheline_size])
])

AC_DEFUN([AX_AUTODETECT_CACHELINE_SIZE],
[
 m4_define([get_from_sys_cpu], [`head -n 1 $1`])
 AC_CHECK_FILE($1,
  [
    AC_MSG_CHECKING([content of $1 as cache_sz/log2_cacheline_size/issubst])
    autodetect_cacheline_size=get_from_sys_cpu($1);
    AS_CASE([$autodetect_cacheline_size],
          [128],[vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=7],
          # Sets default cache line size to 64B
          [vpp_defines_cacheline_size=yes; vpp_log2_cacheline_size=6]
    )
    AC_MSG_RESULT([$autodetect_cacheline_size/$vpp_log2_cacheline_size/$vpp_defines_cacheline_size])
  ],
  [AX_READ_PROC_CPUINFO]
 )
])

AC_DEFUN([AX_VPP_DETECT_CACHELINE_SIZE],
[
 AS_CASE([$build_cpu],
         [x86_64],[AX_AUTODETECT_CACHELINE_SIZE(/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size)],
         [aarch64],[AX_AUTODETECT_CACHELINE_SIZE(/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size)],
         []
 )
])
