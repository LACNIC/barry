#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([barry],[0.0.1],[validadorfort@fortproject.net])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AC_CONFIG_HEADERS([src/config.h])
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_HEADER_STDBOOL

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])
AC_SEARCH_LIBS([X509_get_version], [crypto], [],
	[AC_MSG_ERROR([unable to find the X509_get_version() function])])
AC_SEARCH_LIBS([backtrace],[execinfo],
	[have_backtrace="yes"], [have_backtrace="no"])
AM_CONDITIONAL([BACKTRACE_ENABLED], [test "x$have_backtrace" != "xno"])
PKG_CHECK_MODULES([XML2], [libxml-2.0])
PKG_CHECK_MODULES([CHECK], [check], [usetests=yes], [usetests=no])
AM_CONDITIONAL([USE_TESTS], [test "x$usetests" = "xyes"])

AC_CONFIG_FILES([Makefile src/Makefile test/unit/Makefile])
AC_OUTPUT
