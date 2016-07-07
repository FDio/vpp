AC_INIT(snat_plugin, 1.0)
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_LIBTOOL
AC_PROG_CC

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,["-DDPDK=${with_dpdk}"])

AC_OUTPUT([Makefile])
