AC_INIT(perftool, 2.0)
AM_INIT_AUTOMAKE

AC_CHECK_LIB([vppinfra], [clib_mem_get_page_size],,
        AC_MSG_ERROR([Please install the vpp-lib package]))
AC_CHECK_HEADER([vppinfra/clib.h],,
        AC_MSG_ERROR([Please install the vpp-dev package]))

AM_PROG_LIBTOOL
AM_PROG_CC_C_O

AC_OUTPUT([Makefile])
