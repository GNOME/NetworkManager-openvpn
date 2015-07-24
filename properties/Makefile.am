SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openvpn.la libnm-openvpn-properties.la

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
        -I$(top_srcdir)/src                             \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\"$(datadir)/locale\"               \
        -DVERSION=\"$(VERSION)\"

libnm_vpn_plugin_openvpn_la_CFLAGS =                    \
        $(common_CFLAGS)                                \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(LIBNM_GTK_CFLAGS)

libnm_openvpn_properties_la_CFLAGS =                \
        -DNM_OPENVPN_OLD                                \
        $(common_CFLAGS)                                \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(LIBNM_GTK_CFLAGS)

libnm_vpn_plugin_openvpn_la_LIBADD =                    \
        $(GTK_LIBS)                                     \
        $(LIBNM_GLIB_LIBS)                              \
        $(LIBNM_GTK_LIBS)                               \
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
