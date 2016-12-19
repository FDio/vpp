AC_INIT([vpp], [17.04])
LT_INIT
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_AS
AM_PROG_LIBTOOL
AC_PROG_YACC

AC_ARG_WITH(tools_only,
              AC_HELP_STRING([--with-tools-only],[Only build tools]),
              [with_tools_only=1],
              [with_tools_only=0])

AM_CONDITIONAL(WITH_TOOLS_ONLY, test "$with_tools_only" = "1")

AC_ARG_ENABLE(tests,
              AC_HELP_STRING([--enable-tests],[Enable unit tests]),
              [enable_tests=1],
              [enable_tests=0])

AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" = "1")

AC_ARG_WITH(unix,
            AC_HELP_STRING([--with-unix],[Compile unix version of clib]),
	    [],
	    [case $host_os in
	      darwin* | linux*) with_unix=yes;;
	      *) with_unix=no;;
	      esac])

AM_CONDITIONAL(WITH_UNIX, test "$with_unix" = "yes")

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use DPDK]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(pre-data,
            AC_HELP_STRING([--with-pre-data],[Set buffer rewrite space]),
	    [case $with_pre_data in
	       128) ;;
	       256) ;;
               *) with_pre_data="pre-data-not-set" ;;
	     esac], [with_pre_data=128])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])
AC_SUBST(PRE_DATA_SIZE,[$with_pre_data])

AC_ARG_WITH(dpdk_crypto,
            AC_HELP_STRING([--with-dpdk-crypto],[Use DPDK cryptodev]),
            [with_dpdk_crypto=1],
            [with_dpdk_crypto=0])

AC_ARG_ENABLE(dpdk-shared,
              AC_HELP_STRING([--enable-dpdk-shared],[Link with DPDK shared lib]),
              [enable_dpdk_shared=1],
              [enable_dpdk_shared=0])

AC_ARG_WITH(ipsec,
            AC_HELP_STRING([--without-ipsec],[Disable ipsec]),
            [with_ipsec=0],
            [with_ipsec=1])

AC_ARG_WITH(ipv6sr,
            AC_HELP_STRING([--without-ipv6sr],[Disable ipv6sr]),
            [with_ipv6sr=0],
            [with_ipv6sr=1])

AM_CONDITIONAL(ENABLE_DPDK_SHARED, test "$enable_dpdk_shared" = "1")
AC_SUBST(DPDK,["-DDPDK=${with_dpdk} -DDPDK_SHARED_LIB=${enable_dpdk_shared}"])

AM_CONDITIONAL(WITH_DPDK_CRYPTO, test "$with_dpdk_crypto" = "1")
AC_SUBST(DPDK_CRYPTO,[-DDPDK_CRYPTO=${with_dpdk_crypto}])

AM_CONDITIONAL(WITH_IPSEC, test "$with_ipsec" = "1")
AC_SUBST(IPSEC,[-DIPSEC=${with_ipsec}])

AM_CONDITIONAL(WITH_IPV6SR, test "$with_ipv6sr" = "1")
AC_SUBST(IPV6SR,[-DIPV6SR=${with_ipv6sr}])

AM_COND_IF(
	[ENABLE_DPDK_SHARED],
	[
		AC_CHECK_HEADERS(
			[rte_config.h],
			[], [AC_MSG_ERROR([DPDK header files not found])],
		)
		AC_CHECK_LIB(
			[dpdk], [rte_eal_init],
			[], [AC_MSG_ERROR([DPDK shared library not found])],
		)
	],
)


AC_DEFUN([PLUGIN_ENABLED],
[
   AC_ARG_ENABLE($1_plugin,
       AC_HELP_STRING([--disable-$1-plugin], [Do not build $1 plugin]),
              [enable_the_plugin=0],
              [enable_the_plugin=1])
if test "x$enable_the_plugin" = x1; then
     AC_SUBST($1_srcdir,[plugins/$1-plugin])
fi
AM_CONDITIONAL(ENABLE_$1_PLUGIN, test "$enable_the_plugin" = "1")
])

AC_DEFUN([PLUGIN_DISABLED],
[
   AC_ARG_ENABLE($1_plugin,
       AC_HELP_STRING([--enable-$1-plugin], [Build $1 plugin]),
              [enable_the_plugin=1],
              [enable_the_plugin=0])
if test "x$enable_the_plugin" = x1; then
     AC_SUBST($1_srcdir,[plugins/$1-plugin])
fi
AM_CONDITIONAL(ENABLE_$1_PLUGIN, test "$enable_the_plugin" = "1")
])

# To add a new plugin subdirectory:
#
# add PLUGIN(new) below, and
# add the following to Makefile.am:
#
# if ENABLE_new_PLUGIN
# SUBDIRS += new-plugin
# endif

PLUGIN_ENABLED(sixrd)
PLUGIN_ENABLED(ila)
PLUGIN_ENABLED(flowperpkt)

AC_OUTPUT([Makefile])

AC_MSG_RESULT([
==============================================================================
$PACKAGE $VERSION
prefix:		${prefix}
cflags:		${CFLAGS}
cppflags:	${CPPFLAGS}
ldflags:	${LDFLAGS}
libdir:		${libdir}
includedir:	${includedir}
==============================================================================
])


