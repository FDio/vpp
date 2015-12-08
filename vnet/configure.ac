AC_INIT(vnet, 1.1)
AM_INIT_AUTOMAKE
AM_SILENT_RULES

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AM_PROG_AS

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(virl,
            AC_HELP_STRING([--with-virl],[Compile for virl citizenship]),
            [with_virl=1],
            [with_virl=0])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])

AM_CONDITIONAL(WITH_VIRL, test "$with_virl" = "1")
AC_SUBST(VIRL,[-DVIRL=${with_virl}])

AC_OUTPUT([Makefile])
