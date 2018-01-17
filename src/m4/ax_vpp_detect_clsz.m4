

AC_DEFUN([AX_READ_FILE_MACRO],
[
 AC_MSG_CHECKING([for $1 against ($2,$3) in $4 ])
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

AC_DEFUN([AX_DPDK_DETECT_CLSZ],
[
 AX_READ_FILE_MACRO(RTE_CACHE_LINE_SIZE,64,128,rte_config.h)

 AS_CASE([$VAL_RTE_CACHE_LINE_SIZE],
         [64],[dpdk_defines_clsz=yes; dpdk_log2_clsz=6],
         [128],[dpdk_defines_clsz=yes; dpdk_log2_clsz=7],
         [dpdk_defines_clsz=no]
 )
])

AC_DEFUN([AX_READ_PROC_CPUINFO],
[
 m4_define([read_midr_impl],
           [`awk '/implementer/ {print $[]4;exit}' /proc/cpuinfo`])
 m4_define([read_midr_partnum],
           [`awk '/part/ {print $[]4;exit}' /proc/cpuinfo`])
 limpl=read_midr_impl()
 lpart=read_midr_partnum()
 AS_CASE([$limpl],
  [0x43], [AS_CASE([$lpart],
                   [0x0a1],[vpp_defines_clsz=yes; vpp_log2_clsz=7],
                   [0x0a2],[vpp_defines_clsz=yes; vpp_log2_clsz=7],
                   [0x0a3],[vpp_defines_clsz=yes; vpp_log2_clsz=7],
                   [0x0b1],[vpp_defines_clsz=yes; vpp_log2_clsz=7],
                   [0x0b2],[vpp_defines_clsz=yes; vpp_log2_clsz=7],
                   [vpp_defines_clsz=no; vpp_log2_clsz=6]
           )],
  [vpp_defines_clsz=no; vpp_log2_clsz=5]
 )
 AC_MSG_NOTICE([Detected: Impl/Part/log2csz as $limpl/$lpart/$vpp_log2_clsz])
])

AC_DEFUN([AX_AUTODETECT_CLSZ],
[
 m4_define([get_from_sys_cpu], [`head -n 1 $1`])
 AC_CHECK_FILE($1,
 [autodetect_clsz=get_from_sys_cpu($1);
  AC_MSG_NOTICE([content of $1: $autodetect_clsz])
 ],
 [AX_READ_PROC_CPUINFO]
 )
])

AC_DEFUN([AX_VPP_DETECT_CLSZ],
[
 AS_CASE([$build_cpu],
         [x86_64],[AX_AUTODETECT_CLSZ(/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size)],
         [aarch64],[AX_AUTODETECT_CLSZ(/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size)],
         []
 )
])

