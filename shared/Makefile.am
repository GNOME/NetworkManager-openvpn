noinst_LTLIBRARIES = \
	libnm-vpn-plugin-openvpn-shared.la \
	libnm-vpn-editor-utils-shared.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-shared.la
endif

shared_sources = \
    nm-utils/nm-shared-utils.c \
    nm-utils/nm-shared-utils.h \
    utils.c \
    utils.h \
    nm-service-defines.h

###############################################################################

libnm_vpn_plugin_openvpn_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_vpn_plugin_openvpn_shared_la_SOURCES= \
    $(shared_sources)

libnm_vpn_plugin_openvpn_shared_la_LIBADD = \
    $(LIBNM_LIBS)

###############################################################################

libnm_openvpn_shared_la_SOURCES = \
    $(shared_sources)

libnm_openvpn_shared_la_CPPFLAGS = \
    -DNM_VPN_OLD \
    $(LIBNM_GLIB_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_openvpn_shared_la_LIBADD = \
    $(LIBNM_GLIB_LIBS)

###############################################################################

libnm_vpn_editor_utils_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    -I$(top_srcdir)/shared

libnm_vpn_editor_utils_shared_la_SOURCES = \
    nm-vpn/nm-vpn-plugin-utils.c \
    nm-vpn/nm-vpn-plugin-utils.h

libnm_vpn_editor_utils_shared_la_LIBADD = \
    $(LIBNM_LIBS) \
    -ldl

###############################################################################

EXTRA_DIST = \
     nm-utils/gsystem-local-alloc.h \
     nm-utils/nm-glib.h \
     nm-utils/nm-macros-internal.h \
     nm-utils/nm-test-utils.h \
     nm-default.h

