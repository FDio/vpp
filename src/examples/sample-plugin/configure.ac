AC_INIT(vpp_plugins, 1.0)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC

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

AC_DEFUN([ENABLE_ARG],
[
  AC_ARG_ENABLE($1,
    AC_HELP_STRING(patsubst([--enable-$1],[_],[-]), $2),
    [enable_$1=yes n_enable_$1=1],
    [enable_$1=no n_enable_$1=0])
  AM_CONDITIONAL(m4_toupper(ENABLE_$1), test "$enable_$1" = "yes")
  m4_append([list_of_enabled], [$1], [, ])
])

CC_CHECK_FLAG("-Wno-address-of-packed-member")
AS_IF([test "$cc_flag_check" = yes],
	[CFLAGS="${CFLAGS} -Wno-address-of-packed-member"], [])

AC_OUTPUT([Makefile])

AC_CONFIG_MACRO_DIR([m4])
