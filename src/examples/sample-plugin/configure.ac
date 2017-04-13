AC_INIT(vpp_plugins, 1.0)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

AC_ARG_VAR(VPP_DIR,[ vpp build directory ])
AM_CONDITIONAL([VPP_DIR_SET], [test ! -z "$VPP_DIR"])

AC_ARG_ENABLE([debug],
[  --enable-debug    Turn on debugging],
 [if test x$enableval = xyes; then
    AC_DEFINE(DEBUG, 1, [Define this to enable debug.])
    debug=true
 fi], [debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_PROG_CC

AC_OUTPUT([Makefile])

AC_CONFIG_MACRO_DIR([m4])
