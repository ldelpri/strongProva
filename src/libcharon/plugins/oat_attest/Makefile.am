AM_CPPFLAGS = \
    -I$(top_surdir)/src/libstrongswan \
    -I$(top_srcdir)/src/libhydra \
    -I$(top_srcdir)/src/libcharon \
    -I$(top_srcdir)/src/libjson-c

AM_CFLAGS = \
    $(PLUGINS_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-oat-attest.la
else
plugin_LTLIBRARIES = libstrongswan-oat-attest.la
endif

libstrongswan_oat_attest_la_SOURCES = \
    oat_attest_listener.c oat_attest_plugin.c \
    oat_attest_listener.h oat_attest_plugin.h

libstrongswan_oat_attest_la_LDFLAGS = -module -avoid-version
