SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openvpn-properties.la libnm-openvpn-properties-old.la

libnm_openvpn_properties_la_SOURCES =                   \
        nm-openvpn.c                                    \
        nm-openvpn.h                                    \
        auth-helpers.c                                  \
        auth-helpers.h                                  \
        import-export.c                                 \
        import-export.h

libnm_openvpn_properties_old_la_SOURCES =               \
        $(libnm_openvpn_properties_la_SOURCES)

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

libnm_openvpn_properties_la_CFLAGS =                    \
        $(common_CFLAGS)                                \
        $(LIBNM_CFLAGS)                                 \
        $(LIBNMA_CFLAGS)

libnm_openvpn_properties_old_la_CFLAGS =                \
        -DNM_OPENVPN_OLD                                \
        $(common_CFLAGS)                                \
        $(NM_CFLAGS)                                    \
        $(NMGTK_CFLAGS)

common_LIBADD =                                         \
        $(GTK_LIBS)                                     \
        $(top_builddir)/common/libnm-openvpn-common.la

libnm_openvpn_properties_la_LIBADD =                    \
        $(common_LIBADD)                                \
        $(LIBNM_LIBS)                                   \
        $(LIBNMA_LIBS)

libnm_openvpn_properties_old_la_LIBADD =                \
        $(common_LIBADD)                                \
        $(NM_LIBS)                                      \
        $(NMGTK_LIBS)

libnm_openvpn_properties_la_LDFLAGS =                   \
        -avoid-version

libnm_openvpn_properties_old_la_LDFLAGS =               \
        $(libnm_openvpn_properties_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
