SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openvpn.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-openvpn-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openvpn-properties.la
endif
endif

plugin_sources = \
        nm-openvpn-editor-plugin.c \
        nm-openvpn-editor-plugin.h \
        import-export.c \
        import-export.h

editor_sources = \
        nm-openvpn-editor.c \
        nm-openvpn-editor.h \
        auth-helpers.c \
        auth-helpers.h

uidir = $(datadir)/gnome-vpn-properties/openvpn
if WITH_GNOME
ui_DATA = nm-openvpn-dialog.ui
endif

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        -I$(top_srcdir)/shared                          \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_openvpn_la_SOURCES = \
        $(plugin_sources)

libnm_vpn_plugin_openvpn_la_CFLAGS =                    \
        $(common_CFLAGS)                                \
        -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
        -DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
        $(LIBNM_CFLAGS)

libnm_vpn_plugin_openvpn_la_LIBADD = \
        $(LIBNM_LIBS) \
        $(top_builddir)/shared/libnm-vpn-editor-utils-shared.la \
        $(top_builddir)/shared/libnm-vpn-plugin-openvpn-shared.la

libnm_vpn_plugin_openvpn_la_LDFLAGS = \
        -avoid-version \
        -Wl,--version-script=$(srcdir)/libnm-vpn-plugin-openvpn.ver

###############################################################################

libnm_vpn_plugin_openvpn_editor_la_SOURCES = \
        $(editor_sources)

libnm_vpn_plugin_openvpn_editor_la_CFLAGS = \
        $(common_CFLAGS) \
        $(GTK_CFLAGS) \
        -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
        $(LIBNM_CFLAGS) \
        $(LIBNMA_CFLAGS)

libnm_vpn_plugin_openvpn_editor_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_LIBS) \
        $(LIBNMA_LIBS) \
        $(top_builddir)/shared/libnm-vpn-plugin-openvpn-shared.la

libnm_vpn_plugin_openvpn_editor_la_LDFLAGS = \
        -avoid-version \
        -Wl,--version-script=$(srcdir)/libnm-vpn-plugin-openvpn-editor.ver

###############################################################################

libnm_openvpn_properties_la_SOURCES = \
        $(plugin_sources) \
        $(editor_sources)

libnm_openvpn_properties_la_CFLAGS =                \
        -DNM_OPENVPN_OLD \
        $(common_CFLAGS)                                \
        $(GTK_CFLAGS) \
        -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(LIBNM_GTK_CFLAGS)

libnm_openvpn_properties_la_LIBADD =                \
        $(GTK_LIBS)                                     \
        $(LIBNM_GLIB_LIBS)                              \
        $(LIBNM_GTK_LIBS)                               \
        $(top_builddir)/shared/libnm-openvpn-shared.la

libnm_openvpn_properties_la_LDFLAGS = \
        -avoid-version \
        -Wl,--version-script=$(srcdir)/libnm-openvpn-properties.ver

###############################################################################

libnm_vpn_plugin_openvpn_test_la_SOURCES = $(libnm_vpn_plugin_openvpn_la_SOURCES)
libnm_vpn_plugin_openvpn_test_la_CFLAGS = $(libnm_vpn_plugin_openvpn_la_CFLAGS)
libnm_vpn_plugin_openvpn_test_la_LIBADD = $(libnm_vpn_plugin_openvpn_la_LIBADD)
libnm_vpn_plugin_openvpn_test_la_LDFLAGS = \
    -avoid-version

libnm_openvpn_properties_test_la_SOURCES = $(libnm_openvpn_properties_la_SOURCES)
libnm_openvpn_properties_test_la_CFLAGS = $(libnm_openvpn_properties_la_CFLAGS)
libnm_openvpn_properties_test_la_LIBADD = $(libnm_openvpn_properties_la_LIBADD)
libnm_openvpn_properties_test_la_LDFLAGS = \
    -avoid-version

###############################################################################

noinst_LTLIBRARIES = \
    libnm-vpn-plugin-openvpn-test.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-properties-test.la
endif

CLEANFILES = *.bak *~

EXTRA_DIST = \
        libnm-vpn-plugin-openvpn.ver \
        libnm-vpn-plugin-openvpn-editor.ver \
        libnm-openvpn-properties.ver \
        nm-openvpn-dialog.ui

