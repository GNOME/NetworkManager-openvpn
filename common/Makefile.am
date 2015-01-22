noinst_LTLIBRARIES=libnm-openvpn-common.la

libnm_openvpn_common_la_CPPFLAGS = \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
        -I$(top_srcdir)/src/

libnm_openvpn_common_la_SOURCES= \
	utils.c \
	utils.h \
	nm-glib-compat.h

libnm_openvpn_common_la_LIBADD = \
	$(NM_LIBS)

EXTRA_DIST = nm-glib-compat.h
