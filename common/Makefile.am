noinst_LTLIBRARIES=libnm-openvpn-common.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-common-old.la
endif

libnm_openvpn_common_la_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
        -I$(top_srcdir)/src/

libnm_openvpn_common_old_la_CPPFLAGS = \
	-DNM_OPENVPN_OLD \
	$(LIBNM_GLIB_CFLAGS) \
        -I$(top_srcdir)/src/

libnm_openvpn_common_la_SOURCES= \
	utils.c \
	utils.h \
	nm-glib-compat.h

libnm_openvpn_common_old_la_SOURCES = \
	$(libnm_openvpn_common_la_SOURCES)

libnm_openvpn_common_la_LIBADD = \
	$(LIBNM_LIBS)

libnm_openvpn_common_old_la_LIBADD = \
	$(LIBNM_GLIB_LIBS)

EXTRA_DIST = nm-glib-compat.h
