
AC_INIT(snat_plugin, 1.0)
AM_INIT_AUTOMAKE

AC_PROG_LIBTOOL
AM_PROG_AS
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_WITH(plugin-toolkit,
            AC_HELP_STRING([--with-plugin-toolkit],
            [build using the vpp toolkit]),
            [with_plugin_toolkit=${prefix}/include],
            [with_plugin_toolkit=.])

AC_SUBST(TOOLKIT_INCLUDE,[${with_plugin_toolkit}])
AM_CONDITIONAL(WITH_PLUGIN_TOOLKIT, test "$with_plugin_toolkit" != ".")
AC_OUTPUT([Makefile])
