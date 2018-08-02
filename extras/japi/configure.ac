AC_INIT(japi, 18.10)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

PKG_CHECK_MODULES([CHECK], [check], [HAVE_CHECK=1], [HAVE_CHECK=0])
AM_CONDITIONAL([USE_CHECK],[test "$HAVE_CHECK" -eq 1])

AC_PROG_CC
AC_PROG_CXX

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

CC_CHECK_FLAG("-Wno-address-of-packed-member")
AS_IF([test "$cc_flag_check" = yes],
        [CFLAGS="${CFLAGS} -Wno-address-of-packed-member"], [])

AM_CONDITIONAL(ENABLE_ACL_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_NAT_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_L2E_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_GBP_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_PPPOE_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_GTPU_PLUGIN, test "yes" = "yes")
AM_CONDITIONAL(ENABLE_IOAM_PLUGIN, test "yes" = "yes")

AX_VPP_FIND_JDK8
AC_SUBST(JAVA_HOME)
AC_SUBST(JAVAC)
AC_SUBST(JAVAH)
AC_SUBST(JAR)

AS_CASE([$host_cpu],
	[x86_64], [CPU_FLAGS="-march=corei7 -mtune=corei7-avx"],
	[aarch64], [CPU_FLAGS="-march=armv8-a+crc"],
	[CPU_FLAGS=""],
)
AC_SUBST([CPU_FLAGS])

AC_OUTPUT([Makefile java/Makefile])

AC_CONFIG_MACRO_DIR([m4])
