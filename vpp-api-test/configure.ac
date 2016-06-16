AC_INIT(vpp-api-test, 1.0)
LT_INIT
AM_INIT_AUTOMAKE

AM_PROG_AS
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_WITH(q-plugin-prefix,
            AC_HELP_STRING([--with-q-plugin-prefix],[vlib plugin prefix]),
       	    [case $with_q_plugin_prefix in
	       *) ;;
             esac])

AC_ARG_WITH(q-platform,
            AC_HELP_STRING([--with-q-platform],[Build version for given platform (qnative)]),
	    [case $with_q_platform in
	       qnative) ;;
               vpp) with_q_platform=vpp;;
	       *) with_q_platform=qnative;;
	     esac])

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(non_inline_data,
            AC_HELP_STRING([--with-non-inline-data],
            [For handling non-inline data buffer]),
            [with_inline_data=0],
            [with_inline_data=1])

AC_SUBST(INLINE_DATA,[-DINLINE_DATA=${with_inline_data}])
AC_SUBST(Q_PLATFORM_DEFINE,[-DQ_PLATFORM_${with_q_platform}])
AC_SUBST(Q_PLATFORM_PLUGPATH,[-DQ_PLUGIN_PREFIX=${with_q_plugin_prefix}])
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])
AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")

AC_OUTPUT([Makefile])
