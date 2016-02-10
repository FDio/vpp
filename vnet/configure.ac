AC_INIT(vnet, 1.1)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AS

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(virl,
            AC_HELP_STRING([--with-virl],[Compile for virl citizenship]),
            [with_virl=1],
            [with_virl=0])

AC_ARG_WITH(ipsec,
            AC_HELP_STRING([--without-ipsec],[Disable ipsec]),
            [with_ipsec=0],
            [with_ipsec=1])

AC_ARG_WITH(vcgn,
            AC_HELP_STRING([--without-vcgn],[Disable vcgn]),
            [with_vcgn=0],
            [with_vcgn=1])

AC_ARG_WITH(ipv6sr,
            AC_HELP_STRING([--without-ipv6sr],[Disable ipv6sr]),
            [with_ipv6sr=0],
            [with_ipv6sr=1])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])

AM_CONDITIONAL(WITH_VIRL, test "$with_virl" = "1")
AC_SUBST(VIRL,[-DVIRL=${with_virl}])

AM_CONDITIONAL(WITH_IPSEC, test "$with_ipsec" = "1")
AC_SUBST(IPSEC,[-DIPSEC=${with_ipsec}])

AM_CONDITIONAL(WITH_VCGN, test "$with_vcgn" = "1")
AC_SUBST(VCGN,[-DVCGN=${with_vcgn}])

AM_CONDITIONAL(WITH_IPV6SR, test "$with_ipv6sr" = "1")
AC_SUBST(IPV6SR,[-DIPV6SR=${with_ipv6sr}])

AC_OUTPUT([Makefile])
