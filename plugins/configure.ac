AC_INIT(core_plugins, 1.0)
LT_INIT
AM_INIT_AUTOMAKE

AM_PROG_AS
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_ENABLE(tests,
              AC_HELP_STRING([--enable-tests], [Build unit tests]),
              [enable_tests=1],
              [enable_tests=0])

AC_ARG_WITH(plugin-toolkit,
            AC_HELP_STRING([--with-plugin-toolkit],
            [build using the vpp toolkit]),
            [with_plugin_toolkit=${prefix}/include],
            [with_plugin_toolkit=.])

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_SUBST(TOOLKIT_INCLUDE,[${with_plugin_toolkit}])
AM_CONDITIONAL(WITH_PLUGIN_TOOLKIT, test "$with_plugin_toolkit" != ".")
AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" = "1")

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,["-DDPDK=${with_dpdk}"])


#
# Please DO NOT, UNDER ANY CIRCUMSTANCES enable or disable
# plugins by "clever" manipulation of the arguments to AC_ARG_ENABLE
#
# Instead, please configure the default set of plugins in 
# .../build-data/platforms/<platform>.mk, by adding --enable-XXX-plugin
# stanzas to plugins_configure_args_<platform> 

# The following per-plugin boilerplate is begging for an additional
# macro, but the first 10 tries at making one didn't work. Another day.

#
# Sample plugin
#
AC_ARG_ENABLE(sample_plugin,
              AC_HELP_STRING([--enable-sample-plugin], [Build sample plugin]),
              [enable_sample_plugin=1],
              [enable_sample_plugin=0])

if test "x$enable_sample_plugin" = x1; then
   AC_CONFIG_SUBDIRS([sample-plugin])
fi

AM_CONDITIONAL(ENABLE_SAMPLE_PLUGIN, test "$enable_sample_plugin" = "1")

#
# SIXRD plugin
#
AC_ARG_ENABLE(sixrd_plugin,
              AC_HELP_STRING([--enable-sixrd-plugin], [Build sixrd plugin]),
              [enable_sixrd_plugin=1],
              [enable_sixrd_plugin=0])

if test "x$enable_sixrd_plugin" = x1; then
   AC_CONFIG_SUBDIRS([sixrd-plugin])
fi

AM_CONDITIONAL(ENABLE_SIXRD_PLUGIN, test "$enable_sixrd_plugin" = "1")

#
# IOAM plugin
#
AC_ARG_ENABLE(ioam_plugin,
              AC_HELP_STRING([--enable-ioam-plugin], [Build ioam plugin]),
              [enable_ioam_plugin=1],
              [enable_ioam_plugin=0])

if test "x$enable_ioam_plugin" = x1; then
   AC_CONFIG_SUBDIRS([ioam-plugin])
fi

AM_CONDITIONAL(ENABLE_IOAM_PLUGIN, test "$enable_ioam_plugin" = "1")

#
# VCGN plugin
#
AC_ARG_ENABLE(vcgn_plugin,
              AC_HELP_STRING([--enable-vcgn-plugin], [Build vcgn plugin]),
              [enable_vcgn_plugin=1],
              [enable_vcgn_plugin=0])

if test "x$enable_vcgn_plugin" = x1; then
   AC_CONFIG_SUBDIRS([vcgn-plugin])
fi

AM_CONDITIONAL(ENABLE_VCGN_PLUGIN, test "$enable_vcgn_plugin" = "1")

#
# SNAT plugin
#
AC_ARG_ENABLE(snat_plugin,
              AC_HELP_STRING([--enable-snat-plugin], [Build snat plugin]),
              [enable_snat_plugin=1],
              [enable_snat_plugin=0])

if test "x$enable_snat_plugin" = x1; then
   AC_CONFIG_SUBDIRS([snat-plugin])
fi

AM_CONDITIONAL(ENABLE_SNAT_PLUGIN, test "$enable_snat_plugin" = "1")


AC_OUTPUT([Makefile])
