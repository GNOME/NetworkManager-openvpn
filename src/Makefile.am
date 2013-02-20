AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENVPN_LOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)

libexec_PROGRAMS = nm-openvpn-service nm-openvpn-service-openvpn-helper

nm_openvpn_service_SOURCES = \
	nm-openvpn-service.c \
	nm-openvpn-service.h

nm_openvpn_service_LDADD = \
	$(NM_LIBS) \
        $(top_builddir)/common/libnm-openvpn-common.la

nm_openvpn_service_openvpn_helper_SOURCES = \
	nm-openvpn-service-openvpn-helper.c

nm_openvpn_service_openvpn_helper_LDADD = \
	$(DBUS_LIBS) \
	$(NM_LIBS)

CLEANFILES = *~
