SUBDIRS = conf

INCLUDES = -I${top_srcdir}

noinst_PROGRAMS = test-import-export

test_import_export_SOURCES = \
	test-import-export.c

test_import_export_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NETWORK_MANAGER_CFLAGS) \
	$(DBUS_CFLAGS)

test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(GCONF_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(DBUS_LIBS) \
	$(NETWORK_MANAGER_LIBS) \
	$(top_builddir)/properties/libnm-openvpn-properties.la

if WITH_TESTS

check-local: test-import-export
	$(abs_builddir)/test-import-export $(abs_srcdir)/conf $(abs_builddir)/conf

endif

