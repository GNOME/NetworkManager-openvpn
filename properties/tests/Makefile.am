SUBDIRS = conf

AM_CFLAGS = -I${top_srcdir}

noinst_PROGRAMS = test-import-export

test_import_export_SOURCES = \
	test-import-export.c

test_import_export_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(top_builddir)/properties/libnm-vpn-plugin-openvpn.la

if WITH_TESTS

check-local: test-import-export
	$(abs_builddir)/test-import-export $(abs_srcdir)/conf $(abs_builddir)/conf

endif

