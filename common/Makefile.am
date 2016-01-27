noinst_LTLIBRARIES=libnm-vpn-plugin-openvpn-common.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-common.la
endif

libnm_vpn_plugin_openvpn_common_la_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_openvpn_common_la_CPPFLAGS = \
	-DNM_OPENVPN_OLD \
	$(LIBNM_GLIB_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_vpn_plugin_openvpn_common_la_SOURCES= \
	utils.c \
	utils.h

libnm_openvpn_common_la_SOURCES = \
	$(libnm_vpn_plugin_openvpn_common_la_SOURCES)

libnm_vpn_plugin_openvpn_common_la_LIBADD = \
	$(LIBNM_LIBS)

libnm_openvpn_common_la_LIBADD = \
	$(LIBNM_GLIB_LIBS)
