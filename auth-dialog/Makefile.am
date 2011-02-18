libexec_PROGRAMS = nm-openvpn-auth-dialog

nm_openvpn_auth_dialog_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(NM_CFLAGS)		\
	$(GNOMEKEYRING_CFLAGS) \
	-I$(top_srcdir)/
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"

nm_openvpn_auth_dialog_SOURCES = \
	main.c \
	gnome-two-password-dialog.c \
	gnome-two-password-dialog.h

nm_openvpn_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(NM_LIBS) \
	$(top_builddir)/common-gnome/libnm-openvpn-common-gnome.la \
	$(top_builddir)/common/libnm-openvpn-common.la

CLEANFILES = *~
