AC_INIT(g2, 3.0)
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_CHECK_LIB([vppinfra], [clib_mem_get_page_size],,
        AC_MSG_ERROR([Please install the vpp-lib package]))
AC_CHECK_HEADER([vppinfra/clib.h],,
        AC_MSG_ERROR([Please install the vpp-dev package]))

PKG_CHECK_MODULES(g2, gtk+-2.0)

AC_OUTPUT([Makefile])
