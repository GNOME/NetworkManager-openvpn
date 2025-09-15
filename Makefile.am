AUTOMAKE_OPTIONS = subdir-objects

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes \
	--with-gtk4

libexec_PROGRAMS =

noinst_LTLIBRARIES =

EXTRA_DIST =

CLEANFILES =

check_programs =

noinst_PROGRAMS =

SUBDIRS = \
	. \
	po

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-openvpn-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openvpn-service.name

nmvpnsysusersdir = $(prefix)/lib/sysusers.d
nmvpnsysusers_DATA = nm-openvpn-sysusers.conf

nmvpntmpfilesdir = $(prefix)/lib/tmpfiles.d
nmvpntmpfiles_DATA = nm-openvpn-tmpfiles.conf

uidir = $(datadir)/gnome-vpn-properties/openvpn
ui_DATA =

###############################################################################

shared_sources = \
	shared/nm-utils/nm-shared-utils.c \
	shared/utils.c

###############################################################################

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
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS)

noinst_LTLIBRARIES += src/libnm-utils.la

src_libnm_utils_la_SOURCES = $(shared_sources)
src_libnm_utils_la_CPPFLAGS = $(src_cppflags)
src_libnm_utils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

libexec_PROGRAMS += src/nm-openvpn-service

src_nm_openvpn_service_CPPFLAGS = $(src_cppflags)
src_nm_openvpn_service_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
src_nm_openvpn_service_LDADD = \
	src/libnm-utils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)
EXTRA_src_nm_openvpn_service_DEPENDENCIES = \
	linker-script-binary.ver

libexec_PROGRAMS += src/nm-openvpn-service-openvpn-helper

src_nm_openvpn_service_openvpn_helper_CPPFLAGS = $(src_cppflags)
src_nm_openvpn_service_openvpn_helper_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
src_nm_openvpn_service_openvpn_helper_LDADD = \
	src/libnm-utils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)
EXTRA_src_nm_openvpn_service_openvpn_helper_DEPENDENCIES = \
	linker-script-binary.ver

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

# Include a prebuilt file in tarball, to avoid hitting
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	gtk4/nm-openvpn-dialog.ui

CLEANFILES += \
	gtk4/nm-openvpn-dialog.ui \
	gtk4/resources.c \
	properties/resources.c \
	properties/resources.h

EXTRA_DIST += \
	properties/gresource.xml

plugin_sources = \
	properties/nm-openvpn-editor-plugin.c \
	properties/nm-openvpn-editor-plugin.h \
	properties/import-export.c \
	properties/import-export.h

editor_sources = \
	properties/nm-openvpn-editor.c \
	properties/nm-openvpn-editor.h

properties_cppflags = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS)

###############################################################################

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-utils.la

properties_libnm_vpn_plugin_openvpn_utils_la_SOURCES = \
	$(shared_sources)

properties_libnm_vpn_plugin_openvpn_utils_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_openvpn_utils_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-core.la

properties_libnm_vpn_plugin_openvpn_core_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_openvpn_core_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_openvpn_core_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-utils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn.la

properties_libnm_vpn_plugin_openvpn_la_SOURCES =
properties_libnm_vpn_plugin_openvpn_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-core.la
properties_libnm_vpn_plugin_openvpn_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-openvpn.ver

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-openvpn-editor.la
endif

properties_libnm_vpn_plugin_openvpn_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_vpn_plugin_openvpn_editor_la_SOURCES = \
	properties/resources.c \
	properties/resources.h

properties_libnm_vpn_plugin_openvpn_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_openvpn_editor_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-utils.la \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_openvpn_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-openvpn-editor.ver

###############################################################################

if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-openvpn-editor.la
endif

properties_libnm_gtk4_vpn_plugin_openvpn_editor_la_SOURCES = \
	$(editor_sources)

nodist_properties_libnm_gtk4_vpn_plugin_openvpn_editor_la_SOURCES = \
	gtk4/resources.c \
	properties/resources.h

properties_libnm_gtk4_vpn_plugin_openvpn_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS)

properties_libnm_gtk4_vpn_plugin_openvpn_editor_la_LIBADD = \
	properties/libnm-vpn-plugin-openvpn-utils.la \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS)

properties_libnm_gtk4_vpn_plugin_openvpn_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-openvpn-editor.ver

###############################################################################

EXTRA_DIST += \
	properties/libnm-vpn-plugin-openvpn.ver \
	properties/libnm-vpn-plugin-openvpn-editor.ver \
	properties/nm-openvpn-dialog.ui

###############################################################################

properties_tests_cppflags = \
	-DNETWORKMANAGER_COMPILATION_TEST \
	-DTEST_SRCDIR="\"$(abs_srcdir)/properties/tests\"" \
	-DTEST_BUILDDIR="\"$(abs_builddir)/properties/tests\"" \
	-I$(srcdir)/shared \
	-I$(srcdir)/properties \
	$(GLIB_CFLAGS)

check_programs += properties/tests/test-import-export

properties_tests_test_import_export_SOURCES = \
	properties/tests/test-import-export.c

properties_tests_test_import_export_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	$(properties_tests_cppflags) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_tests_test_import_export_LDADD = \
	properties/libnm-vpn-plugin-openvpn-core.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

EXTRA_DIST += \
	properties/tests/conf/compress.ovpn \
	properties/tests/conf/iso885915.ovpn \
	properties/tests/conf/mtu-disc.ovpn \
	properties/tests/conf/password.conf \
	properties/tests/conf/pkcs12.ovpn \
	properties/tests/conf/pkcs12-with-ca.ovpn \
	properties/tests/conf/port.ovpn \
	properties/tests/conf/rport.ovpn \
	properties/tests/conf/static.key \
	properties/tests/conf/static.ovpn \
	properties/tests/conf/static2.ovpn \
	properties/tests/conf/tls.ovpn \
	properties/tests/conf/tls2.ovpn \
	properties/tests/conf/tls3.ovpn \
	properties/tests/conf/tls4.ovpn \
	properties/tests/conf/tun-opts.conf \
	properties/tests/conf/proxy-http.ovpn \
	properties/tests/conf/httpauthfile \
	properties/tests/conf/proxy-socks.ovpn \
	properties/tests/conf/proxy-http-with-auth.ovpn \
	properties/tests/conf/keysize.ovpn \
	properties/tests/conf/connect-timeout.ovpn \
	properties/tests/conf/device.ovpn \
	properties/tests/conf/device-notype.ovpn \
	properties/tests/conf/keepalive.ovpn \
	properties/tests/conf/ping-with-exit.ovpn \
	properties/tests/conf/ping-with-restart.ovpn \
	properties/tests/conf/push-peer-info.ovpn \
	properties/tests/conf/route.ovpn \
	properties/tests/conf/server-poll-timeout.ovpn \
	properties/tests/conf/crl-file.ovpn \
	properties/tests/conf/crl-dir.ovpn \
	properties/tests/conf/tls-inline.ovpn \
	properties/tests/conf/tls-inline-ca.pem \
	properties/tests/conf/tls-inline-cert.pem \
	properties/tests/conf/tls-inline-crl-verify-file.pem \
	properties/tests/conf/tls-inline-key.pem \
	properties/tests/conf/tls-inline-ta.pem \
	properties/tests/conf/data-ciphers-fallback.ovpn \
	properties/tests/conf/proto-udp.ovpn \
	properties/tests/conf/proto-udp4.ovpn \
	properties/tests/conf/proto-udp6.ovpn \
	properties/tests/conf/proto-tcp.ovpn \
	properties/tests/conf/proto-tcp4.ovpn \
	properties/tests/conf/proto-tcp6.ovpn \
	properties/tests/conf/proto-tcp4-client.ovpn \
	properties/tests/conf/proto-tcp6-client.ovpn

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-openvpn-auth-dialog
endif

auth_dialog_nm_openvpn_auth_dialog_SOURCES = \
	$(shared_sources) \
	auth-dialog/main.c
if WITH_GTK4
auth_dialog_nm_openvpn_auth_dialog_CPPFLAGS = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS) \
	$(LIBSECRET_CFLAGS)
auth_dialog_nm_openvpn_auth_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	$(LIBSECRET_LIBS)
else
auth_dialog_nm_openvpn_auth_dialog_CPPFLAGS = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DEFAULT \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS)
auth_dialog_nm_openvpn_auth_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)
endif
auth_dialog_nm_openvpn_auth_dialog_LDFLAGS = \
	-Wl,--version-script="$(srcdir)/linker-script-binary.ver"
EXTRA_auth_dialog_nm_openvpn_auth_dialog_DEPENDENCIES = \
	linker-script-binary.ver

###############################################################################

appdatadir = $(datadir)/metainfo
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-openvpn.metainfo.xml.in

appdata/network-manager-openvpn.metainfo.xml: appdata/network-manager-openvpn.metainfo.xml.in
	$(AM_V_GEN)$(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

nm-openvpn-service.name: $(srcdir)/nm-openvpn-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

nm-openvpn-sysusers.conf: $(srcdir)/nm-openvpn-sysusers.conf.in
	$(AM_V_GEN) sed -e 's|[@]LOCALSTATEDIR[@]|$(localstatedir)|g' \
	    $^ >$@

nm-openvpn-tmpfiles.conf: $(srcdir)/nm-openvpn-tmpfiles.conf.in
	$(AM_V_GEN) sed -e 's|[@]LOCALSTATEDIR[@]|$(localstatedir)|g' \
	    $^ >$@

# we always build the tests during regular build.
noinst_PROGRAMS += $(check_programs)

TESTS = $(check_programs)

EXTRA_DIST += \
	linker-script-binary.ver \
	nm-openvpn-service.name.in \
	nm-openvpn-sysusers.conf.in \
	nm-openvpn-tmpfiles.conf.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	\
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

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

ACLOCAL_AMFLAGS = -I m4
