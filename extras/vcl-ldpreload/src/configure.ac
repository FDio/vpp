AC_INIT([vcl-ldpreload], [1.0], [vpp-dev@fd.io])
LT_INIT
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AM_PROG_AS
AM_PROG_LIBTOOL
AC_PROG_YACC
AM_PATH_PYTHON

AC_ARG_VAR(VPP_DIR,[ vpp build directory ])
AM_CONDITIONAL([VPP_DIR_SET], [test ! -z "$VPP_DIR"])

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


AC_DEFUN([PRINT_VAL], [ AC_MSG_RESULT(AC_HELP_STRING($1,$2)) ])


###############################################################################
# configure arguments
###############################################################################

# --enable-X

AC_ARG_ENABLE([vpp-debug],
[  --enable-vpp-debug    Use vpp debug native build libraries],
 [if test x$enableval = xyes; then
    AC_DEFINE(VPP_DEBUG, 1, [Define this to use vpp debug native build libraries.])
    vpp_debug=true
 fi], [vpp_debug=false])
AM_CONDITIONAL([VPP_DEBUG], [test x$vpp_debug = xtrue])

AC_ARG_ENABLE([vcl-ldpreload-debug],
[  --enable-vcl-ldpreload-debug    Turn on vcl-ldpreload debugging],
 [if test x$enableval = xyes; then
    AC_DEFINE(VCL_LDPRELOAD_DEBUG, 1, [Define this to enable vcl-ldpreload debug.])
    vcl_ldpreload_debug=true
 fi], [vcl_ldpreload_debug=false])
AM_CONDITIONAL([VCL_LDPRELOAD_DEBUG], [test x$vcl_ldpreload_debug = xtrue])

# --disable-X

# --with-X

# --without-X

AC_ARG_WITH(unix,
            AC_HELP_STRING([--with-unix],[Compile unix version of clib]),
	    [],
	    [case $host_os in
	      darwin* | linux*) with_unix=yes;;
	      *) with_unix=no;;
	      esac])

AM_CONDITIONAL(WITH_UNIX, test "$with_unix" = "yes")


###############################################################################
# Substitutions and defines
###############################################################################


# Silence following noise:
# ar: `u' modifier ignored since `D' is the default (see `U')
AR_FLAGS=cr
AC_SUBST(AR_FLAGS)


###############################################################################
# Dependency checks
###############################################################################

###############################################################################
# Output
###############################################################################

AC_OUTPUT

AC_MSG_RESULT([==============================================================================])
PRINT_VAL([version], $PACKAGE $VERSION)
PRINT_VAL([prefix], ${prefix})
PRINT_VAL([exec_prefix], ${exec_prefix})
PRINT_VAL([libdir], ${libdir})
PRINT_VAL([includedir], ${includedir})
PRINT_VAL([CFLAGS], ${CFLAGS})
PRINT_VAL([CPPFLAGS], ${CPPFLAGS})
PRINT_VAL([LDFLAGS], ${LDFLAGS})

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
AC_MSG_RESULT([==============================================================================])


