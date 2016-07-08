AC_INIT(vnet, 1.1)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS(config/config.h)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_PROG_CC

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(ipsec,
            AC_HELP_STRING([--without-ipsec],[Disable ipsec]),
            [with_ipsec=0],
            [with_ipsec=1])

AC_ARG_WITH(ipv6sr,
            AC_HELP_STRING([--without-ipv6sr],[Disable ipv6sr]),
            [with_ipv6sr=0],
            [with_ipv6sr=1])

AC_ARG_ENABLE(tests,
              AC_HELP_STRING([--enable-tests], [Build unit tests]),
              [enable_tests=1],
              [enable_tests=0])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])

AM_CONDITIONAL(WITH_IPSEC, test "$with_ipsec" = "1")
AC_SUBST(IPSEC,[-DIPSEC=${with_ipsec}])

AM_CONDITIONAL(WITH_IPV6SR, test "$with_ipv6sr" = "1")
AC_SUBST(IPV6SR,[-DIPV6SR=${with_ipv6sr}])

AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" = "1")

AC_OUTPUT([Makefile])
