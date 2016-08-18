AC_INIT(jvpp, 16.12)
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

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

AC_OUTPUT([Makefile])

