AC_INIT(perftool, 2.0)
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_CHECK_LIB([vppinfra], [clib_mem_get_page_size],,
        AC_MSG_ERROR([Please install the vpp-lib package]))
AC_CHECK_HEADER([vppinfra/clib.h],,
        AC_MSG_ERROR([Please install the vpp-dev package]))

AM_PROG_LIBTOOL

AC_OUTPUT([Makefile])
