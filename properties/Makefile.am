SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openvpn-properties.la

libnm_openvpn_properties_la_SOURCES = \
	nm-openvpn.c \
	nm-openvpn.h \
	auth-helpers.c \
	auth-helpers.h \
	import-export.c \
	import-export.h

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA = nm-openvpn-dialog.ui

libnm_openvpn_properties_la_CFLAGS =                    \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                                    \
        $(GNOMEKEYRING_CFLAGS)                          \
        $(DISABLE_DEPRECATED)                           \
        -I$(top_srcdir)/                                \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DLOCALEDIR=\"$(datadir)/locale\"               \
        -DVERSION=\"$(VERSION)\"

libnm_openvpn_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS) \
        $(top_builddir)/common/libnm-openvpn-common.la

libnm_openvpn_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
