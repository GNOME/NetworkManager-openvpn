AUTOMAKE_OPTIONS = foreign subdir-objects

libexec_PROGRAMS =

EXTRA_DIST =

CLEANFILES =

SUBDIRS = \
	. \
	properties \
	po

if WITH_GNOME
SUBDIRS += auth-dialog
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openvpn-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openvpn-service.name

###############################################################################

shared_sources = \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/utils.c \
	shared/utils.h \
	shared/nm-service-defines.h \
	$(NULL)

src_cppflags = \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENVPN_LOCALEDIR=\"$(datadir)/locale\" \
	-DG_LOG_DOMAIN=\"nm-openvpn\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS)

libexec_PROGRAMS += src/nm-openvpn-service

src_nm_openvpn_service_SOURCES = \
	$(shared_sources) \
	src/nm-openvpn-service.c \
	src/nm-openvpn-service.h

src_nm_openvpn_service_CFLAGS = $(src_cppflags)

src_nm_openvpn_service_LDADD = \
	$(LIBNM_LIBS)

libexec_PROGRAMS += src/nm-openvpn-service-openvpn-helper

src_nm_openvpn_service_openvpn_helper_SOURCES = \
	$(shared_sources) \
	src/nm-openvpn-service-openvpn-helper.c

src_nm_openvpn_service_openvpn_helper_CPPFLAGS = $(src_cppflags)

src_nm_openvpn_service_openvpn_helper_LDADD = \
	$(LIBNM_LIBS)

CLEANFILES += src/*~

###############################################################################

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-openvpn-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openvpn-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openvpn-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-openvpn.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-openvpn-service.name: $(srcdir)/nm-openvpn-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

EXTRA_DIST += \
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	shared/utils.c \
	shared/utils.h \
	$(NULL)

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes

EXTRA_DIST += \
	nm-openvpn-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

ACLOCAL_AMFLAGS = -I m4
