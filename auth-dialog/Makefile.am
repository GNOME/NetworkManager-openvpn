libexec_PROGRAMS = nm-openvpn-auth-dialog

nm_openvpn_auth_dialog_CPPFLAGS =			\
	$(GLIB_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(NM_CFLAGS)		\
	$(NMGTK_CFLAGS)		\
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
	$(NM_LIBS) \
	$(NMGTK_LIBS) \
	$(LIBSECRET_LIBS) \
	$(top_builddir)/common/libnm-openvpn-common-old.la

CLEANFILES = *~
