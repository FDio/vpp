AC_INIT(vom, 18.07)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

PKG_CHECK_MODULES([CHECK], [check], [HAVE_CHECK=1], [HAVE_CHECK=0])
AM_CONDITIONAL([USE_CHECK],[test "$HAVE_CHECK" -eq 1])

AC_PROG_CC
AC_PROG_CXX

AC_DEFUN([CHECK_VAPI_HDR],
[
  AC_CHECK_HEADERS([vapi/$1.api.vapi.hpp],
    [enable_$1_plugin=yes],
    [ AC_MSG_WARN([$1 disabled]) ], [])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1_PLUGIN), test "$enable_$1_plugin" = "yes")
])

AC_LANG(C++)
CHECK_VAPI_HDR(acl)
CHECK_VAPI_HDR(nat)
CHECK_VAPI_HDR(l2e)
CHECK_VAPI_HDR(gbp)

AC_OUTPUT([Makefile vom/Makefile])

AC_CONFIG_MACRO_DIR([m4])
