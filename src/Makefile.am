AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
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

libexec_PROGRAMS = \
	nm-openvpn-service \
	nm-openvpn-service-openvpn-helper

shared_sources = \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-shared-utils.h \
	$(top_srcdir)/shared/utils.c \
	$(top_srcdir)/shared/utils.h \
	$(top_srcdir)/shared/nm-service-defines.h \
	$(NULL)

###############################################################################

nm_openvpn_service_SOURCES = \
	$(shared_sources) \
	nm-openvpn-service.c \
	nm-openvpn-service.h

nm_openvpn_service_LDADD = \
	$(LIBNM_LIBS) \
	$(LIBSECRET_LIBS)

###############################################################################

nm_openvpn_service_openvpn_helper_SOURCES = \
	$(shared_sources) \
	nm-openvpn-service-openvpn-helper.c

nm_openvpn_service_openvpn_helper_LDADD = \
	$(LIBNM_LIBS)

###############################################################################

CLEANFILES = *~
