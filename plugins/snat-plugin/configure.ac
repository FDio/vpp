AC_INIT(snat_plugin, 1.0)
AC_CONFIG_MACRO_DIR([../../vpp-api/java/m4])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_LIBTOOL
AC_PROG_CC

if test -f /usr/bin/lsb_release  && test `lsb_release -si` == "Ubuntu"  && test `lsb_release -sr` == "14.04"  && test -d /usr/lib/jvm/java-8-openjdk-amd64/ ; then
    JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/
    JAVAC=${JAVA_HOME}/bin/javac
    PATH=${JAVA_HOME}/bin/:${PATH}
    break
fi

AX_CHECK_JAVA_HOME
AX_PROG_JAVAC
AX_PROG_JAVAH
AX_PROG_JAR
AX_PROG_JAVADOC
AX_PROG_JAVA

AC_ARG_WITH(dpdk,
            AC_HELP_STRING([--with-dpdk],[Use DPDK]),
            [with_dpdk=1],
            [with_dpdk=0])

AM_CONDITIONAL(WITH_DPDK, test "$with_dpdk" = "1")
AC_SUBST(DPDK,["-DDPDK=${with_dpdk}"])

AC_OUTPUT([Makefile])
