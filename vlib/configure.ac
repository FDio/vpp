AC_INIT(vlib, 1.1)
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use the Intel dpdk]),
            [with_dpdk=1],
            [with_dpdk=0])

AC_ARG_WITH(pre-data,
            AC_HELP_STRING([--with-pre-data],[Set buffer rewrite space]),
	    [case $with_pre_data in
	       128) ;;
	       256) ;;
               *) with_pre_data="pre-data-not-set" ;;
	     esac], [with_pre_data=128])

AC_ARG_WITH(non_inline_data,
            AC_HELP_STRING([--with-non-inline-data],
            [For handling non-inline data buffer]),
            [with_inline_data=0],
            [with_inline_data=1])

AC_SUBST(INLINE_DATA,[-DINLINE_DATA=${with_inline_data}])
AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,[-DDPDK=${with_dpdk}])
AC_SUBST(PRE_DATA_SIZE,[$with_pre_data])

AC_OUTPUT([Makefile])
