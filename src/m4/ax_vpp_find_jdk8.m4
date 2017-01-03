

AC_DEFUN([AX_VPP_FIND_JDK8],
[
while true
do
  if test "${JAVA_HOME+set}" = set ; then
    AC_MSG_CHECKING([${JAVA_HOME} for Java 8 compiler])
    JAVAC=${JAVA_HOME}/bin/javac
    JAVAH=${JAVA_HOME}/bin/javah
    JAR=${JAVA_HOME}/bin/jar
    JAVA_VERSION=$(${JAVA_HOME}/bin/javac -source 8 -version 2>&1)
    if test 0 -eq "$?"; then
      JAVA_VERSION=$(echo "${JAVA_VERSION}" | cut -d\  -f2)
      AC_MSG_RESULT([ok])
    else
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([Java in ${JAVA_HOME} (path specified in JAVA_HOME) cannot compile Java 8 code])
    fi
    break
  fi

  for dir in $(find /usr/lib/jvm/* -maxdepth 0 -type d); do
    AC_MSG_CHECKING([${dir} for Java 8 compiler])
    JAVA_VERSION=$(${dir}/bin/javac -source 8 -version 2>&1)
    if test 0 -eq "$?"; then
      JAVA_VERSION=$(echo "${JAVA_VERSION}" | cut -d\  -f2)
      JAVA_HOME=${dir}
      JAVAC=${dir}/bin/javac
      JAVAH=${dir}/bin/javah
      JAR=${dir}/bin/jar
      AC_MSG_RESULT([found version $JAVA_VERSION])
      break
    else
      JAVA_VERSION=""
      AC_MSG_RESULT([no])
    fi
  done

  test "${JAVA_HOME}set" = set && AC_MSG_ERROR([Could not find Java 8 compiler])
  break
done
])
