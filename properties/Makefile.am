SUBDIRS = . tests

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openvpn-properties-new.la libnm-openvpn-properties-old.la

libnm_openvpn_properties_new_la_SOURCES = \
	nm-openvpn.c \
	nm-openvpn.h \
	auth-helpers.c \
	auth-helpers.h \
	import-export.c \
	import-export.h

libnm_openvpn_properties_old_la_SOURCES = \
	nm-openvpn.c \
	nm-openvpn.h \
	auth-helpers.c \
	auth-helpers.h \
	import-export.c \
	import-export.h

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA = nm-openvpn-dialog.ui

libnm_openvpn_properties_new_la_CFLAGS =                \
        -DNM_OPENVPN_NEW                                \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                                    \
        $(NMGTK_CFLAGS)                                 \
        -I$(top_srcdir)/src                             \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\"$(datadir)/locale\"               \
        -DVERSION=\"$(VERSION)\"

libnm_openvpn_properties_old_la_CFLAGS =                \
        -DNM_OPENVPN_OLD                                \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                                    \
        $(NMGTK_CFLAGS)                                 \
        -I$(top_srcdir)/src                             \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\"$(datadir)/locale\"               \
        -DVERSION=\"$(VERSION)\"

libnm_openvpn_properties_new_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS) \
        $(NMGTK_LIBS) \
        $(top_builddir)/common/libnm-openvpn-common.la

libnm_openvpn_properties_old_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS) \
        $(NMGTK_LIBS) \
        $(top_builddir)/common/libnm-openvpn-common.la

libnm_openvpn_properties_new_la_LDFLAGS =   \
        -avoid-version

libnm_openvpn_properties_old_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
