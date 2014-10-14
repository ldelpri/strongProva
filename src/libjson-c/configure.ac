AC_PREREQ(2.52)
AC_CONFIG_MACRO_DIR([m4])
# Process this file with autoconf to produce a configure script.
AC_INIT([json-c], 0.12.99, [json-c@googlegroups.com])

AM_INIT_AUTOMAKE

AC_PROG_MAKE_SET

AC_SUBST([ipseclibdir], [${libdir}/libipsec])

# Checks for programs.

# Checks for libraries.

# Checks for header files.
AM_PROG_CC_C_O
AC_CONFIG_HEADER(config.h)
AC_CONFIG_HEADER(json_config.h)
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h limits.h strings.h syslog.h unistd.h [sys/cdefs.h] [sys/param.h] stdarg.h locale.h endian.h)
AC_CHECK_HEADER(inttypes.h,[AC_DEFINE([JSON_C_HAVE_INTTYPES_H],[1],[Public define for json_inttypes.h])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_VPRINTF
AC_FUNC_MEMCMP
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS(strcasecmp strdup strerror snprintf vsnprintf vasprintf open vsyslog strncasecmp setlocale)
AC_CHECK_DECLS([INFINITY], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([nan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isnan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isinf], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([_isnan], [], [], [[#include <float.h>]])
AC_CHECK_DECLS([_finite], [], [], [[#include <float.h>]])


AM_PROG_LIBTOOL


AC_CONFIG_FILES([
Makefile
json-c.pc
tests/Makefile
json-c-uninstalled.pc
])

AC_OUTPUT

