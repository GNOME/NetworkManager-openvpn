libexec_PROGRAMS = nm-openvpn-auth-dialog

nm_openvpn_auth_dialog_CPPFLAGS =			\
	$(GLIB_CFLAGS)			\
	$(GTK_CFLAGS)			\
	$(LIBNM_CFLAGS)			\
	$(LIBNMA_CFLAGS)		\
	$(LIBSECRET_CFLAGS) \
	-I$(top_srcdir)/shared \
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

nm_openvpn_auth_dialog_SOURCES = \
	$(top_srcdir)/shared/utils.c \
	$(top_srcdir)/shared/utils.h \
	main.c

nm_openvpn_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

CLEANFILES = *~
