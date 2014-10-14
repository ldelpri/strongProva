
ACLOCAL_AMFLAGS = -I m4

ipseclib_LTLIBRARIES = libjson-c.la 
#libjsonx_includedir = $(libdir)/json-c-@VERSION@
#
#libjsonx_include_HEADERS = \
#	json_config.h

libjson_c_la_SOURCES = \
	arraylist.c \
	debug.c \
	json_c_version.c \
	json_object.c \
	json_object_iterator.c \
	json_tokener.c \
	json_util.c \
	linkhash.c \
	printbuf.c \
	random_seed.c \
	arraylist.h \
	bits.h \
	debug.h \
	json.h \
	json_config.h \
	json_c_version.h \
	json_inttypes.h \
	json_object.h \
	json_object_iterator.h \
	json_object_private.h \
	json_tokener.h \
	json_util.h \
	linkhash.h \
	printbuf.h \
	random_seed.h

libjson_c_la_LIBADD = \
    $(top_builddir)/src/libstrongswan/libstrongswan.la

AM_CPPFLAGS = \
    -I$(top_srcdir)/src/libstrongswan

AM_LDFLAGS = \
    -no-undefined

EXTRA_DIST = Android.mk


