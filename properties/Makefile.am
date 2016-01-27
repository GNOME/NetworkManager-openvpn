SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openvpn.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openvpn-properties.la
endif

libnm_vpn_plugin_openvpn_la_SOURCES =                   \
        nm-openvpn.c                                    \
        nm-openvpn.h                                    \
        auth-helpers.c                                  \
        auth-helpers.h                                  \
        import-export.c                                 \
        import-export.h

libnm_openvpn_properties_la_SOURCES =               \
        $(libnm_vpn_plugin_openvpn_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA = nm-openvpn-dialog.ui

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        -I$(top_srcdir)/common                          \
        -I$(top_srcdir)/shared                          \
        -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\"$(datadir)/locale\"

libnm_vpn_plugin_openvpn_la_CFLAGS =                    \
        $(common_CFLAGS)                                \
        $(LIBNM_CFLAGS)                                 \
        $(LIBNMA_CFLAGS)

libnm_openvpn_properties_la_CFLAGS =                \
        -DNM_OPENVPN_OLD \
        $(common_CFLAGS)                                \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(LIBNM_GTK_CFLAGS)

libnm_vpn_plugin_openvpn_la_LIBADD =                    \
        $(GTK_LIBS)                                     \
        $(LIBNM_LIBS)                                   \
        $(LIBNMA_LIBS)                                  \
        $(top_builddir)/common/libnm-vpn-plugin-openvpn-common.la

libnm_openvpn_properties_la_LIBADD =                \
        $(GTK_LIBS)                                     \
        $(LIBNM_GLIB_LIBS)                              \
        $(LIBNM_GTK_LIBS)                               \
        $(top_builddir)/common/libnm-openvpn-common.la

libnm_vpn_plugin_openvpn_la_LDFLAGS =                   \
        -avoid-version

libnm_openvpn_properties_la_LDFLAGS =               \
        $(libnm_vpn_plugin_openvpn_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
