AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(NM_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)\""

noinst_PROGRAMS = test-helper-config

test_helper_config_SOURCES = \
	test-helper-config.c \
	../helper-config.c \
	../helper-config.h

test_helper_config_LDADD = \
	$(GLIB_LIBS) \
	$(NM_LIBS)

TESTS = test-helper-config

EXTRA_DIST = \
	test-basic-init.conf \
	test-basic-restart.conf
