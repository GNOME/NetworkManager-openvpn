noinst_LTLIBRARIES=libnm-openvpn-common-gnome.la

libnm_openvpn_common_gnome_la_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_openvpn_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_openvpn_common_gnome_la_LIBADD = \
	$(NM_LIBS) \
	$(GNOMEKEYRING_LIBS)

