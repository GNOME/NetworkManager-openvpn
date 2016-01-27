AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-I$(top_srcdir)/shared \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENVPN_LOCALEDIR=\"$(datadir)/locale\" \
	-DG_LOG_DOMAIN=\"nm-openvpn\"

libexec_PROGRAMS = nm-openvpn-service nm-openvpn-service-openvpn-helper

nm_openvpn_service_SOURCES = \
	nm-openvpn-service.c \
	nm-openvpn-service.h \
	nm-openvpn-service-defines.h

nm_openvpn_service_LDADD = \
	$(LIBNM_LIBS) \
        $(top_builddir)/common/libnm-vpn-plugin-openvpn-common.la

nm_openvpn_service_openvpn_helper_SOURCES = \
	nm-openvpn-service-openvpn-helper.c

nm_openvpn_service_openvpn_helper_LDADD = \
	$(LIBNM_LIBS)

CLEANFILES = *~
