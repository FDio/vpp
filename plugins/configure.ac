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

AC_DEFUN([PLUGIN],
[
   AC_ARG_ENABLE($1_plugin,
       AC_HELP_STRING([--enable-$1-plugin], [Build $1 plugin]),
              [enable_the_plugin=1],
              [enable_the_plugin=0])
if test "x$enable_the_plugin" = x1; then
   AC_CONFIG_SUBDIRS($1-plugin)
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

PLUGIN(sample)
PLUGIN(sixrd)
PLUGIN(ioam)
PLUGIN(vcgn)
PLUGIN(snat)

AC_OUTPUT([Makefile])
