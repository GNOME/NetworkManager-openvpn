noinst_LTLIBRARIES=libnm-vpn-plugin-openvpn-common.la libnm-openvpn-common.la

libnm_vpn_plugin_openvpn_common_la_CPPFLAGS = \
	$(NM_CFLAGS) \
        -I$(top_srcdir)/src/

libnm_openvpn_common_la_CPPFLAGS = \
	-DNM_OPENVPN_OLD \
	$(NM_CFLAGS) \
        -I$(top_srcdir)/src/

libnm_vpn_plugin_openvpn_common_la_SOURCES= \
	utils.c \
	utils.h \
	nm-glib-compat.h

libnm_openvpn_common_la_SOURCES = \
	$(libnm_vpn_plugin_openvpn_common_la_SOURCES)

libnm_vpn_plugin_openvpn_common_la_LIBADD = \
	$(NM_LIBS)

libnm_openvpn_common_la_LIBADD = \
	$(NM_LIBS)

EXTRA_DIST = nm-glib-compat.h
