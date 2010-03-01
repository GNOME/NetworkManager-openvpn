noinst_LTLIBRARIES=libnm-openvpn-common.la

libnm_openvpn_common_la_CPPFLAGS = \
	$(NETWORK_MANAGER_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
        -I$(top_srcdir)/src/

libnm_openvpn_common_la_SOURCES= \
	utils.c \
	utils.h

libnm_openvpn_common_gnome_la_LIBADD = \
	$(NETWORK_MANAGER_LIBS)

