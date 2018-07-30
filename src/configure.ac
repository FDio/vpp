AC_INIT([vpp], [18.10], [vpp-dev@fd.io])
LT_INIT
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_FILES([ \
  Makefile \
  plugins/Makefile \
  vpp-api/python/Makefile \
  vpp-api/vapi/Makefile \
  vlib/config.h \
  vppinfra/config.h \
])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CPP
AM_PROG_AS
AM_PROG_LIBTOOL
AM_PATH_PYTHON

AM_CONDITIONAL([CROSSCOMPILE], [test "$cross_compiling" == "yes"])

###############################################################################
# Macros
###############################################################################

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

AC_DEFUN([WITH_ARG],
[
  AC_ARG_WITH($1,
    AC_HELP_STRING(patsubst([--with-$1],[_],[-]), $2),
    [with_$1=yes n_with_$1=1],
    [with_$1=no n_with_$1=0])
  AM_CONDITIONAL(m4_toupper(WITH_$1), test "$with_$1" = "yes")
  m4_append([list_of_with], [$1], [, ])
])

AC_DEFUN([WITHOUT_ARG],
[
  AC_ARG_WITH($1,
    AC_HELP_STRING(patsubst([--without-$1],[_],[-]), $2),
    [with_$1=no n_with_$1=0],
    [with_$1=yes n_with_$1=1])
  AM_CONDITIONAL(m4_toupper(WITH_$1), test "$with_$1" = "yes")
  m4_append([list_of_with], [$1], [, ])
])

AC_DEFUN([PLUGIN_ENABLED],
[
   AC_ARG_ENABLE($1_plugin,
     AC_HELP_STRING([--disable-$1-plugin], [Do not build $1 plugin]),
       [enable_$1_plugin=no],
       [enable_$1_plugin=yes ])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1_PLUGIN), test "$enable_$1_plugin" = "yes")
  m4_append([list_of_plugins], [$1], [, ])
])

AC_DEFUN([PLUGIN_DISABLED],
[
   AC_ARG_ENABLE($1_plugin,
     AC_HELP_STRING([--enable-$1-plugin], [Build $1 plugin]),
       [enable_$1_plugin=yes ],
       [enable_$1_plugin=no])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1_PLUGIN), test "$enable_$1_plugin" = "yes")
  m4_append([list_of_plugins], [$1], [, ])
])

AC_DEFUN([PRINT_VAL], [ AC_MSG_RESULT(AC_HELP_STRING($1,$2)) ])

AC_DEFUN([DPDK_IS_PMD_ENABLED],
[
  AC_MSG_CHECKING([for $1 in rte_config.h])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[#include <rte_config.h>]],
      [[return RTE_$1;]],
    )],
    [with_$2=yes]
    [AC_MSG_RESULT([yes])],
    [with_$2=no]
    [AC_MSG_RESULT([no])]
  )
  AM_CONDITIONAL(m4_toupper(WITH_$2), test "$with_$2" = "yes")
  m4_append_uniq([list_of_with], [$2], [, ])
])

# Check if compiler supports specific flag
AC_DEFUN([CC_CHECK_FLAG],
[
  AC_MSG_CHECKING([if $CC supports $1])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
  [cc_flag_check=yes],
  [cc_flag_check=no]
)
  AC_MSG_RESULT([$cc_flag_check])
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
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

###############################################################################
# configure arguments
###############################################################################

# --enable-X
ENABLE_ARG(tests,	[Enable unit tests])
ENABLE_ARG(dpdk_shared,	[Enable unit tests])
ENABLE_ARG(perftool,	[Enable perftool])
ENABLE_ARG(g2,		[Enable g2])
ENABLE_ARG(dlmalloc,    [Enable dlmalloc])

# --disable-X
DISABLE_ARG(vlib,	[Disable vlib and dependant libs and binaries])
DISABLE_ARG(svm,	[Disable svm and dependant libs and binaries])
DISABLE_ARG(papi,	[Disable Python API bindings])

# --with-X

# --without-X
WITHOUT_ARG(libssl,	[Disable libssl])
WITHOUT_ARG(apicli,	[Disable binary api CLI])
WITHOUT_ARG(mbedtls,	[Disable mbedtls])
WITHOUT_ARG(libnuma,	[for non numa architectures])

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

AM_CONDITIONAL(WITH_UNIX, test "$with_unix" = "yes")

AC_ARG_WITH(pre-data,
            AC_HELP_STRING([--with-pre-data],[Set buffer rewrite space]),
	    [case $with_pre_data in
	       128) ;;
	       256) ;;
               *) with_pre_data="pre-data-not-set" ;;
	     esac], [with_pre_data=128])

AM_CONDITIONAL(ENABLE_DLMALLOC, test "$enable_dlmalloc" = "yes")

###############################################################################
# Target CPU flags
###############################################################################

# Check if compiler supports march=core-avx2
CC_CHECK_FLAG("-march=core-avx2")
AS_IF([test "$cc_flag_check" = yes],
      [march_core_avx2=yes],
      [march_core_avx2=no])
AM_CONDITIONAL([CC_SUPPORTS_AVX2], [test "$march_core_avx2" = "yes"])

# Check if compiler supports march=skylake-avx512
CC_CHECK_FLAG("-march=skylake-avx512")
AS_IF([test "$cc_flag_check" = yes],
  [march_skylake_avx512=yes],
  [march_skylake_avx512=no])
AM_CONDITIONAL([CC_SUPPORTS_AVX512], [test "$march_skylake_avx512" = "yes"])

AS_CASE([$host_cpu],
	[x86_64], [CPU_FLAGS="-march=corei7 -mtune=corei7-avx"],
	[aarch64], [CPU_FLAGS="-march=armv8-a+crc"],
	[CPU_FLAGS=""],
)
AC_SUBST([CPU_FLAGS])

AC_SUBST([CPU_AVX2_FLAGS],"-march=core-avx2 -mtune=core-avx2")
AC_SUBST([CPU_AVX512_FLAGS],"-march=skylake-avx512 -mtune=skylake-avx512")

AM_CONDITIONAL([CPU_X86_64], [test "$host_cpu" = "x86_64"])
AM_CONDITIONAL([CPU_AARCH64], [test "$host_cpu" = "aarch64"])

###############################################################################
# misc compiler flags
###############################################################################

CC_CHECK_FLAG("-Wno-address-of-packed-member")
AS_IF([test "$cc_flag_check" = yes],
	[CFLAGS="${CFLAGS} -Wno-address-of-packed-member"], [])

###############################################################################
# Substitutions and defines
###############################################################################

AC_SUBST(PRE_DATA_SIZE,		[$with_pre_data])
AC_SUBST(LOG2_CACHE_LINE_BYTES, [$with_log2_cache_line_bytes])
AC_SUBST(APICLI,		[-DVPP_API_TEST_BUILTIN=${n_with_apicli}])
AC_SUBST(DLMALLOC,              [${n_enable_dlmalloc}])

AC_DEFINE_UNQUOTED(DPDK_SHARED_LIB,	[${n_enable_dpdk_shared}])
AC_DEFINE_UNQUOTED(WITH_LIBSSL,		[${n_with_libssl}])
AC_DEFINE_UNQUOTED(WITH_MBEDTLS,	[${n_with_mbedtls}])
AC_DEFINE_UNQUOTED(WITH_LIBNUMA,	[${n_with_libnuma}])


# Silence following noise:
# ar: `u' modifier ignored since `D' is the default (see `U')
AR_FLAGS=cr
AC_SUBST(AR_FLAGS)

###############################################################################
# Plugins
###############################################################################

# Please keep alphabetical order
PLUGIN_ENABLED(abf)
PLUGIN_ENABLED(acl)
PLUGIN_ENABLED(avf)
PLUGIN_ENABLED(cdp)
PLUGIN_ENABLED(dpdk)
PLUGIN_ENABLED(flowprobe)
PLUGIN_ENABLED(gbp)
PLUGIN_ENABLED(gtpu)
PLUGIN_ENABLED(igmp)
PLUGIN_ENABLED(ila)
PLUGIN_ENABLED(ioam)
PLUGIN_ENABLED(ixge)
PLUGIN_ENABLED(l2e)
PLUGIN_ENABLED(lacp)
PLUGIN_ENABLED(lb)
PLUGIN_ENABLED(mactime)
PLUGIN_ENABLED(marvell)
PLUGIN_ENABLED(memif)
PLUGIN_ENABLED(pppoe)
PLUGIN_ENABLED(nat)
PLUGIN_ENABLED(map)
PLUGIN_ENABLED(srv6ad)
PLUGIN_ENABLED(srv6am)
PLUGIN_ENABLED(srv6as)
PLUGIN_ENABLED(stn)
PLUGIN_ENABLED(tlsmbedtls)
PLUGIN_ENABLED(tlsopenssl)
PLUGIN_ENABLED(unittest)

###############################################################################
# Dependency checks
###############################################################################
AC_CHECK_FUNC([memfd_create], [AC_DEFINE([HAVE_MEMFD_CREATE], [1], [Define if memfd exists])])

AM_COND_IF([ENABLE_DPDK_SHARED],
[
  AC_CHECK_HEADERS([rte_config.h],
    [],
    [AC_MSG_ERROR([DPDK header files not found])],)
  AC_CHECK_LIB( [dpdk], [rte_eal_init],
    [],
    [AC_MSG_ERROR([DPDK shared library not found])],)
])

with_aesni_mb_lib=no
with_isa_l_crypto_lib=no

DPDK_IS_PMD_ENABLED(LIBRTE_PMD_AESNI_MB, dpdk_aesni_mb_pmd)
DPDK_IS_PMD_ENABLED(LIBRTE_PMD_AESNI_GCM, dpdk_aesni_gcm_pmd)

AM_COND_IF([WITH_DPDK_AESNI_MB_PMD],
[
  AC_CHECK_LIB([IPSec_MB], [submit_job_sse],
	       [with_aesni_mb_lib=yes],
	       [AC_MSG_ERROR([IPSec_MB library not found])])
])

AM_COND_IF([WITH_DPDK_AESNI_GCM_PMD],
[
  AC_CHECK_LIB([IPSec_MB], [submit_job_sse],
    [with_aesni_mb_lib=yes],
    [AC_MSG_ERROR([IPSec_MB library not found])])
])

m4_append([list_of_with], [aesni_mb_lib], [, ])
AM_CONDITIONAL(WITH_AESNI_MB_LIB, test "$with_aesni_mb_lib" = "yes")

m4_append([list_of_with], [isa_l_crypto_lib], [, ])
AM_CONDITIONAL(WITH_ISA_L_CRYPTO_LIB, test "$with_isa_l_crypto_lib" = "yes")

AM_COND_IF([ENABLE_G2],
[
  PKG_CHECK_MODULES(g2, gtk+-2.0)
])

AM_COND_IF([ENABLE_MARVELL_PLUGIN],
[
  AC_CHECK_LIB( [musdk], [pp2_init],
    [],
    [
      AC_MSG_WARN([Marvell MUSDK library with PP2 support not found. Plugin disabled.])
      enable_marvell_plugin=no
      AM_CONDITIONAL(ENABLE_MARVELL_PLUGIN, false)
    ])
])

AM_COND_IF([WITH_MBEDTLS], [],
[
  AC_MSG_WARN([mbedtls not enabled. Disabling tlsmbedtls plugin])
  enable_tlsmbedtls_plugin=no
  AM_CONDITIONAL(ENABLE_TLSMBEDTLS_PLUGIN, false)
])

AM_COND_IF([ENABLE_TLSMBEDTLS_PLUGIN],
[
  AC_CHECK_HEADERS([mbedtls/ssl.h], [],
    [
      AC_MSG_WARN([mbedtls headers not found. TLS engine implementation disabled])
      enable_tlsmbedtls_plugin=no
      AM_CONDITIONAL(ENABLE_TLSMBEDTLS_PLUGIN, false)
    ], [])
])

AM_COND_IF([WITH_LIBSSL],
[
  AC_CHECK_LIB([ssl -lcrypto], [SSL_set_async_callback],
    [
      AC_DEFINE([HAVE_OPENSSL_ASYNC], [1], [Define if new openssl interface exists])
    ])
],
[
  AC_MSG_WARN([openssl not enabled. Disabling tlsopenssl plugin])
  enable_tlsopenssl_plugin=no
  AM_CONDITIONAL(ENABLE_TLSOPENSSL_PLUGIN, false)
])

###############################################################################
# PYTHON
###############################################################################

AM_COND_IF([ENABLE_PAPI],
[
  AM_PATH_PYTHON
])

###############################################################################
# Output
###############################################################################

AC_OUTPUT

AC_MSG_RESULT([==============================================================================])
PRINT_VAL([version], $PACKAGE $VERSION)
PRINT_VAL([prefix], ${prefix})
PRINT_VAL([libdir], ${libdir})
PRINT_VAL([includedir], ${includedir})
PRINT_VAL([CFLAGS], ${CFLAGS})
PRINT_VAL([CPPFLAGS], ${CPPFLAGS})
PRINT_VAL([LDFLAGS], ${LDFLAGS})
PRINT_VAL([LOG2_CACHE_LINE_BYTES], ${with_log2_cache_line_bytes})
PRINT_VAL([DLMALLOC], ${enable_dlmalloc})

AC_MSG_RESULT([])
AC_MSG_RESULT([with:])
m4_foreach([x], m4_dquote(list_of_with), [
  AC_MSG_RESULT(AC_HELP_STRING(x, m4_join([], [${with_], x, [}])))
])

AC_MSG_RESULT([])
AC_MSG_RESULT([enabled:])
m4_foreach([x], m4_dquote(list_of_enabled), [
  AC_MSG_RESULT(AC_HELP_STRING(x, m4_join([], [${enable_], x, [}])))
])

AC_MSG_RESULT([])
AC_MSG_RESULT([plugins:])
m4_foreach([x], m4_dquote(list_of_plugins), [
  AC_MSG_RESULT(AC_HELP_STRING(x, m4_join([], [${enable_], x, [_plugin}])))
])
AC_MSG_RESULT([==============================================================================])


