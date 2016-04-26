# Process this file with autoconf to produce a configure script.
AC_INIT(libvppinfra,1.0,)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS(config/config.h)
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([gnu no-dist-gzip dist-bzip2])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AM_PROG_AS
AM_PROG_LIBTOOL

######################################################################

dnl ------------
dnl Check CFLAGS, CC
dnl ------------
AC_ARG_WITH(cc,
	    AC_HELP_STRING([--with-cc],[Set CC for use as C compiler.]),
	    [CC="$with_cc"])

AC_ARG_WITH(cflags,
	    AC_HELP_STRING([--with-cflags],[Set CFLAGS for use by C compiler.]),
	    [CFLAGS="$with_cflags"])

AC_ARG_WITH(ldflags,
	    AC_HELP_STRING([--with-ldflags],[Set LDFLAGS for linking.]),
	    [LDFLAGS="$with_ldflags"])

######################################################################

AC_ARG_ENABLE(tests,
              AC_HELP_STRING([--enable-tests],[Enable unit tests]),
              [enable_tests=1],
              [enable_tests=0])

AM_CONDITIONAL(ENABLE_TESTS, test "$enable_tests" = "1")

AC_ARG_WITH(unix,
            AC_HELP_STRING([--with-unix],[Compile unix version of clib]),
	    [],
	    [case $host_os in
	      darwin* | linux*) with_unix=yes;;
	      *) with_unix=no;;
	      esac])

AM_CONDITIONAL(WITH_UNIX, test "$with_unix" = "yes")


## Enable 64-bit vector lengths
AC_ARG_WITH(vec64,
	    AC_HELP_STRING([--with-vec64],[Enable 64-bit vector lengths]),
            [with_vec64=1],
            [with_vec64=0])

AC_SUBST(VEC64,[-DCLIB_VEC64=${with_vec64}])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
