AC_INIT([test32], [18.10], [dev-null@fd.io])
LT_INIT
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects foreign -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_FILES([ \
  Makefile \
  vppinfra/config.h \
])
AC_CONFIG_MACRO_DIR([m4])

AC_DEFUN([ENABLE_ARG],
[
  AC_ARG_ENABLE($1,
    AC_HELP_STRING(patsubst([--enable-$1],[_],[-]), $2),
    [enable_$1=yes n_enable_$1=1],
    [enable_$1=no n_enable_$1=0])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1), test "$enable_$1" = "yes")
  m4_append([list_of_enabled], [$1], [, ])
])

AC_DEFUN([DISABLE_ARG],
[
  AC_ARG_ENABLE($1,
    AC_HELP_STRING(patsubst([--disable-$1],[_],[-]), $2),
    [enable_$1=no n_enable_$1=0],
    [enable_$1=yes n_enable_$1=1])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1), test "$enable_$1" = "yes")
  m4_append([list_of_enabled], [$1], [, ])
])

# This function deduces the BUILD HOST cache-line size by
# inspecting /sys and/or /proc depending on the kernel / arch in use
as_fn_log2_cache_line_size_p()
{
  sysfs_cache_path="/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"
  m4_define([read_cache_line_size_from_sysfs], [`head -n 1 $1`])
  m4_define([read_midr_implementer],
            [`awk '/implementer/ {print $[]4;exit}' /proc/cpuinfo`])
  m4_define([read_midr_cpuid],
            [`awk '/part/ {print $[]4;exit}' /proc/cpuinfo`])

  #Check if sysfs path exists,to ignore warning, else do manual mapping
  AC_CHECK_FILE($sysfs_cache_path,
    [
      cache_line_size=read_cache_line_size_from_sysfs($sysfs_cache_path);
      if test $cache_line_size = "32"  ; then
          log2_cache_line_size="5";
      elif test $cache_line_size = "64"  ; then
          log2_cache_line_size="6";
      elif test $cache_line_size = "128"  ; then
          log2_cache_line_size="7";
      fi
      AC_MSG_NOTICE([cache_line_size/log2_cache_line_size deduced as $cache_line_size/$log2_cache_line_size])
    ],
    [
        #Define Implementer Ids here
        implementer_id_cavium=0x43

        #Define CPU Ids here
        cpu_id_cavium_thunderx_cn88xx=0x0a1
        cpu_id_cavium_thunderx2_cn99xx=0x0af

        implementer=read_midr_implementer()
        cpuid=read_midr_cpuid()

        AC_MSG_CHECKING([for implementerid/cpuid to set log2_cache_line_size])

        # Switch case to map log2_cache_line_size for implementer/cpuid combination.
        # Default case of Switch sets log2_cache_line_size to 6
        AS_CASE($implementer,
              #Switch Case for Cavium SoC's
              [$implementer_id_cavium],
                  [AS_CASE($cpuid,
                      #Only ThunderX2 is 64B. Remaining chips are 128B
                      [$cpu_id_cavium_thunderx2_cn99xx],
                            [AC_MSG_RESULT([Cavium/ThunderX2]);log2_cache_line_size=6],
                      [$cpu_id_cavium_thunderx_cn88xx],
                            [AC_MSG_RESULT([Cavium/ThunderX]);log2_cache_line_size=7],
                      [log2_cache_line_size=7;AC_MSG_RESULT([Cavium/OCTEONTx($cpuid)])]
                   )],
              #Add implementer specific case here:

              #Default case: 64B for all SoC's
              [log2_cache_line_size=6;AC_MSG_RESULT([$implementer/$cpuid])]
        )
      AC_MSG_NOTICE([log2_cache_line_size deduced as $log2_cache_line_size])
    ]
  )
  echo $log2_cache_line_size
}
AC_ARG_WITH(log2-cache-line-bytes,
            AC_HELP_STRING([--with-log2-cache-line-bytes],[Set the cache line size, --with-log2-cache-line-bytes=5|6|7|auto]),
	    [case $with_log2_cache_line_bytes in
	      5 | 6 | 7);;
	      auto) with_log2_cache_line_bytes=`as_fn_log2_cache_line_size_p`;;
              *) with_log2_cache_line_bytes="CONFIG_ERROR";;
	      esac],
              [with_log2_cache_line_bytes=`as_fn_log2_cache_line_size_p`])

AC_ARG_WITH(unix,
            AC_HELP_STRING([--with-unix],[Compile unix version of clib]),
	    [],
	    [case $host_os in
	      darwin* | linux*) with_unix=yes;;
	      *) with_unix=no;;
	      esac])

AC_CHECK_FUNC([memfd_create], [AC_DEFINE([HAVE_MEMFD_CREATE], [1], [Define if memfd exists])])

AM_CONDITIONAL(WITH_UNIX, test "$with_unix" = "yes")

ENABLE_ARG(dlmalloc,    [Enable dlmalloc])
DISABLE_ARG(tests,    [disable tests])

AC_PROG_CC
AC_PROG_CPP
AM_PROG_AS
AM_PROG_LIBTOOL

AM_CONDITIONAL(ENABLE_DLMALLOC, test "$enable_dlmalloc" = "yes")

AC_SUBST(LOG2_CACHE_LINE_BYTES, [$with_log2_cache_line_bytes])
AC_SUBST(DLMALLOC,              [${n_enable_dlmalloc}])

AC_OUTPUT
