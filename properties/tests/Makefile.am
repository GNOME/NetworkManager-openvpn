SUBDIRS = conf

AM_CFLAGS = \
    -I${top_srcdir}/shared \
    -I${top_srcdir}/properties \
    -DTEST_SRCDIR="\"$(abs_srcdir)\"" \
    -DTEST_BUILDDIR="\"$(abs_builddir)\""

noinst_PROGRAMS = \
	test-import-export
if WITH_LIBNM_GLIB
noinst_PROGRAMS += test-import-export-glib
endif


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


test_import_export_glib_SOURCES = \
	test-import-export.c

test_import_export_glib_CPPFLAGS = \
	-DNM_OPENVPN_OLD \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

test_import_export_glib_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS) \
	$(top_builddir)/properties/libnm-openvpn-properties.la


TESTS = \
	test-import-export
if WITH_LIBNM_GLIB
TESTS += test-import-export-glib
endif

