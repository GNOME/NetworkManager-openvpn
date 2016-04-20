SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openvpn.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openvpn-properties.la
endif

plugin_sources = \
        nm-openvpn.c \
        nm-openvpn.h \
        auth-helpers.c \
        auth-helpers.h \
        import-export.c \
        import-export.h

libnm_vpn_plugin_openvpn_la_SOURCES = \
        $(plugin_sources)

libnm_openvpn_properties_la_SOURCES = \
        $(plugin_sources)

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA = nm-openvpn-dialog.ui

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
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
        $(top_builddir)/shared/libnm-vpn-plugin-openvpn-shared.la

libnm_openvpn_properties_la_LIBADD =                \
        $(GTK_LIBS)                                     \
        $(LIBNM_GLIB_LIBS)                              \
        $(LIBNM_GTK_LIBS)                               \
        $(top_builddir)/shared/libnm-openvpn-shared.la

libnm_vpn_plugin_openvpn_la_LDFLAGS = \
        -avoid-version \
        -Wl,--version-script=$(srcdir)/libnm-vpn-plugin-openvpn.ver

libnm_openvpn_properties_la_LDFLAGS = \
        -avoid-version \
        -Wl,--version-script=$(srcdir)/libnm-openvpn-properties.ver

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

noinst_LTLIBRARIES = \
    libnm-vpn-plugin-openvpn-test.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-openvpn-properties-test.la
endif

CLEANFILES = *.bak *~

EXTRA_DIST = \
        libnm-vpn-plugin-openvpn.ver \
        libnm-openvpn-properties.ver \
        $(ui_DATA)

