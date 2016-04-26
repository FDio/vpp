AC_INIT(vpp, 1.1)
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AM_PROG_AS
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_ENABLE(dpdk-shared,
              AC_HELP_STRING([--enable-dpdk-shared],[Link with DPDK shared lib]),
              [enable_dpdk_shared=1],
              [enable_dpdk_shared=0])

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
AM_CONDITIONAL(ENABLE_DPDK_SHARED, test "$enable_dpdk_shared" = "1")
AC_SUBST(DPDK,["-DDPDK=${with_dpdk} -DDPDK_SHARED_LIB=${enable_dpdk_shared}"])

AM_COND_IF(
	[ENABLE_DPDK_SHARED],
	[
		AC_CHECK_HEADERS(
			[rte_config.h],
			[], [AC_MSG_ERROR([DPDK header files not found])],
		)
		AC_CHECK_LIB(
			[dpdk], [rte_eal_init],
			[], [AC_MSG_ERROR([DPDK shared library not found])],
		)
	],
)

AM_CONDITIONAL(WITH_IPSEC, test "$with_ipsec" = "1")
AC_SUBST(IPSEC,[-DIPSEC=${with_ipsec}])

AM_CONDITIONAL(WITH_VCGN, test "$with_vcgn" = "1")
AC_SUBST(VCGN,[-DVCGN=${with_vcgn}])

AM_CONDITIONAL(WITH_IPV6SR, test "$with_ipv6sr" = "1")
AC_SUBST(IPV6SR,[-DIPV6SR=${with_ipv6sr}])

AC_OUTPUT([Makefile])
