libexec_PROGRAMS = nm-openvpn-auth-dialog

nm_openvpn_auth_dialog_CPPFLAGS =			\
	$(GLIB_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(LIBNM_GLIB_CFLAGS)		\
	$(LIBNM_GTK_CFLAGS)		\
	$(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"

nm_openvpn_auth_dialog_SOURCES = \
	main.c

nm_openvpn_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS) \
	$(LIBSECRET_LIBS) \
	$(top_builddir)/common/libnm-openvpn-common-old.la

CLEANFILES = *~
