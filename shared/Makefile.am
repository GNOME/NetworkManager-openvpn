noinst_LTLIBRARIES=libnm-vpn-plugin-openvpn-shared.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-shared.la
endif

libnm_vpn_plugin_openvpn_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_openvpn_shared_la_CPPFLAGS = \
    -DNM_OPENVPN_OLD \
    $(LIBNM_GLIB_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_vpn_plugin_openvpn_shared_la_SOURCES= \
    utils.c \
    utils.h \
    nm-openvpn-service-defines.h

libnm_openvpn_shared_la_SOURCES = \
    $(libnm_vpn_plugin_openvpn_shared_la_SOURCES)

libnm_vpn_plugin_openvpn_shared_la_LIBADD = \
    $(LIBNM_LIBS)

libnm_openvpn_shared_la_LIBADD = \
    $(LIBNM_GLIB_LIBS)

EXTRA_DIST = \
     gsystem-local-alloc.h \
     nm-dbus-compat.h \
     nm-default.h \
     nm-glib.h \
     nm-macros-internal.h

