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

AC_SUBST(TOOLKIT_INCLUDE,[${with_plugin_toolkit}])
AM_CONDITIONAL(WITH_PLUGIN_TOOLKIT, test "$with_plugin_toolkit" != ".")
AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" = "1")
AC_OUTPUT([Makefile])
