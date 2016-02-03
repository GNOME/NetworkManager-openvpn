/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>

#include "nm-default.h"

#include "nm-openvpn.h"
#include "nm-openvpn-service-defines.h"
#include "import-export.h"

#include "nm-test-utils.h"

#define TEST_SRCDIR_CONF     TEST_SRCDIR"/conf"
#define TEST_BUILDDIR_CONF   TEST_BUILDDIR"/conf"

#define SRCDIR TEST_SRCDIR_CONF
#define TMPDIR TEST_BUILDDIR_CONF

/*****************************************************************************/

static char *
_create_detail (const char *strfunc)
{
	char *s, *t;

	g_assert (strfunc);
	g_assert (g_str_has_prefix (strfunc, "test_"));

	s = g_strdup (&strfunc[STRLEN ("test_")]);
	while ((t = strchr (s, '_')))
		t[0] = '-';

	g_assert (s[0]);
	return s;
}
#define _CREATE_DETAIL(detail) gs_free char *detail = _create_detail (G_STRFUNC)

static NMVpnEditorPlugin *
_create_plugin (void)
{
	NMVpnEditorPlugin *plugin;
	GError *error = NULL;

	plugin = nm_vpn_editor_plugin_factory (&error);
	g_assert_no_error (error);
	g_assert (OPENVPN_IS_EDITOR_PLUGIN (plugin));
	return plugin;
}
#define _CREATE_PLUGIN(plugin) \
	gs_unref_object NMVpnEditorPlugin *plugin = _create_plugin ()

/*****************************************************************************/

static NMConnection *
get_basic_connection (const char *detail,
                      NMVpnEditorPlugin *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	char *pcf;

	pcf = g_build_path ("/", dir, filename, NULL);
	ASSERT (pcf != NULL,
	        "basic", "failed to create pcf path");

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	if (error)
		FAIL ("basic", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "basic", "error importing %s: (unknown)", pcf);

	g_free (pcf);
	return connection;
}

static void
_check_item (const char *test,
             NMSettingVpn *s_vpn,
             const char *item,
             const char *expected)
{
	const char *value;

	ASSERT (s_vpn != NULL, test, "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, item);
	if (expected == NULL) {
		ASSERT (value == NULL, test, "unexpected '%s' item value (found '%s', expected NULL)",
		        item, value);
		return;
	}

	ASSERT (value != NULL, test, "missing '%s' item value", item);
	ASSERT (strcmp (value, expected) == 0, test,
	        "unexpected '%s' item value (found '%s', expected '%s')",
	        item, value, expected);
}

static void
_check_secret (const char *test,
             NMSettingVpn *s_vpn,
             const char *item,
             const char *expected)
{
	const char *value;

	ASSERT (s_vpn != NULL, test, "missing 'vpn' setting");

	value = nm_setting_vpn_get_secret (s_vpn, item);
	if (expected == NULL) {
		ASSERT (value == NULL, test, "unexpected '%s' secret value (found '%s', expected NULL)",
		        item, value);
		return;
	}

	ASSERT (value != NULL, test, "missing '%s' secret value", item);
	ASSERT (strcmp (value, expected) == 0, test,
	        "unexpected '%s' secret value (found '%s', expected '%s')",
	        item, value, expected);
}

/*****************************************************************************/

static void
test_password_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "password";
	char *expected_cacert;

	connection = get_basic_connection ("password-import", plugin, SRCDIR, "password.conf");
	ASSERT (connection != NULL, "password-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "password-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "password-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "password-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "password-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_cacert = g_build_filename (SRCDIR, "cacert.pem", NULL);
	_check_item ("password-import-data", s_vpn, NM_OPENVPN_KEY_CA, expected_cacert);
	g_free (expected_cacert);

	/* Secrets */
	_check_secret ("password-import-secrets", s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret ("password-import-secrets", s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
save_one_key (const char *key, const char *value, gpointer user_data)
{
	GSList **list = user_data;

	*list = g_slist_append (*list, g_strdup (key));
}

static void
remove_secrets (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	GSList *keys = NULL, *iter;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn)
		return;

	nm_setting_vpn_foreach_secret (s_vpn, save_one_key, &keys);
	for (iter = keys; iter; iter = g_slist_next (iter))
		nm_setting_vpn_remove_secret (s_vpn, (const char *) iter->data);

	g_slist_foreach (keys, (GFunc) g_free, NULL);
	g_slist_free (keys);
}

#define PASSWORD_EXPORTED_NAME "password.ovpntest"
static void
test_password_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("password-export", plugin, SRCDIR, "password.conf");
	ASSERT (connection != NULL, "password-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, PASSWORD_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("password-export", "export failed with missing error");
		else
			FAIL ("password-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("password-export", plugin, TMPDIR, PASSWORD_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "password-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "password-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_tls_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "tls";
	char *expected_path;

	connection = get_basic_connection ("tls-import", plugin, SRCDIR, "tls.ovpn");
	ASSERT (connection != NULL, "tls-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "tls-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "tls-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "tls-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "tls-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	expected_path = g_strdup_printf ("%s/keys/mg8.ca", SRCDIR);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.crt", SRCDIR);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.key", SRCDIR);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_KEY, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/46.key", SRCDIR);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_TA, expected_path);
	g_free (expected_path);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	/* Secrets */
	_check_secret ("tls-import-secrets", s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret ("tls-import-secrets", s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
test_file_contents (const char *id,
                    const char *dir,
                    NMSettingVpn *s_vpn,
                    char *item) {
	const char *path;
	char *path2;
	char *contents;
	char *expected_contents;
	gsize length;
	gsize expected_length;
	char *test;

	test = g_strdup_printf("%s-%s", id, item);

	path = nm_setting_vpn_get_data_item(s_vpn, item);
	ASSERT(g_file_get_contents(path, &contents, &length, NULL), test,
		"failed to open file");
	path2 = g_strdup_printf ("%s/%s-%s.pem", dir, id, item);
	ASSERT(g_file_get_contents(path2, &expected_contents, &expected_length, NULL),
		test, "failed to load test data?!");

	if (length != expected_length || memcmp(contents, expected_contents, length)) {
		g_message ("a>>>[%s]%s<<<a", path2, expected_contents);
		g_message ("b>>>[%s]%s<<<b", path, contents);
		FAIL (test, "file contents were not the same");
	}
	g_free (contents);
	g_free (expected_contents);
	g_free (path2);
	g_free (test);
}

static void
test_tls_inline_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "tls-inline";

	connection = get_basic_connection ("tls-import", plugin, SRCDIR, "tls-inline.ovpn");
	ASSERT (connection != NULL, "tls-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "tls-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "tls-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "tls-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "tls-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CA);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CERT);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_KEY);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_TA);
	_check_item ("tls-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	_check_secret ("tls-import-secrets", s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret ("tls-import-secrets", s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_assert (unlink (TMPDIR"/tls-inline-tls-auth.pem") == 0);

	g_object_unref (connection);
}


#define TLS_EXPORTED_NAME "tls.ovpntest"
static void
test_tls_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("tls-export", plugin, SRCDIR, "tls.ovpn");
	ASSERT (connection != NULL, "tls-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, TLS_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("tls-export", "export failed with missing error");
		else
			FAIL ("tls-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("tls-export", plugin, TMPDIR, TLS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "tls-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "tls-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_pkcs12_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "pkcs12";
	char *expected_path;

	connection = get_basic_connection ("pkcs12-import", plugin, SRCDIR, "pkcs12.ovpn");
	ASSERT (connection != NULL, "pkcs12-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "pkcs12-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "pkcs12-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "pkcs12-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "pkcs12-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", SRCDIR);
	_check_item ("pkcs12-import-data", s_vpn, NM_OPENVPN_KEY_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	_check_secret ("pkcs12-import-secrets", s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret ("pkcs12-import-secrets", s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

#define PKCS12_EXPORTED_NAME "pkcs12.ovpntest"
static void
test_pkcs12_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("pkcs12-export", plugin, SRCDIR, "pkcs12.ovpn");
	ASSERT (connection != NULL, "pkcs12-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, PKCS12_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("pkcs12-export", "export failed with missing error");
		else
			FAIL ("pkcs12-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("pkcs12-export", plugin, TMPDIR, PKCS12_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "pkcs12-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "pkcs12-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_non_utf8_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_cacert = "Attätaenko.pem";
	char *expected_path;
	const char *charset = NULL;

	/* Change charset to ISO-8859-15 to match iso885915.ovpn */
	g_get_charset (&charset);
	setlocale (LC_ALL, "de_DE@euro");
	connection = get_basic_connection ("non-utf8-import", plugin, SRCDIR, "iso885915.ovpn");
	setlocale (LC_ALL, charset);

	ASSERT (connection != NULL, "non-utf8-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "non-utf8-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), "iso885915") == 0,
	        "non-utf8-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "non-utf8-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "non-utf8-import", "missing 'vpn' setting");

	expected_path = g_strdup_printf ("%s/%s", SRCDIR, expected_cacert);
	_check_item ("non-utf8-import-data", s_vpn, NM_OPENVPN_KEY_CA, expected_path);
	g_free (expected_path);

	g_object_unref (connection);
}

static void
test_static_key_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "static";
	char *expected_path;

	connection = get_basic_connection ("static-key-import", plugin, SRCDIR, "static.ovpn");
	ASSERT (connection != NULL, "static-key-import", "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        "static-key-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "static-key-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "static-key-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "static-key-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "10.11.12.13");
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, "1");
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, "10.8.0.2");
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, "10.8.0.1");
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/static.key", SRCDIR);
	_check_item ("static-key-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	_check_secret ("static-key-import-secrets", s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret ("static-key-import-secrets", s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

#define STATIC_KEY_EXPORTED_NAME "static.ovpntest"
static void
test_static_key_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("static-key-export", plugin, SRCDIR, "static.ovpn");
	ASSERT (connection != NULL, "static-key-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, STATIC_KEY_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("static-key-export", "export failed with missing error");
		else
			FAIL ("static-key-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("static-key-export", plugin, TMPDIR, STATIC_KEY_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "static-key-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "static-key-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_port_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *detail, *file, *expected_id, *expected_port;

	nmtst_test_data_unpack_detail (test_data, &detail, &file, &expected_id, &expected_port);

	connection = get_basic_connection (detail, plugin, SRCDIR, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL,
	        detail, "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        detail, "unexpected connection ID");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        detail, "missing 'vpn' setting");

	/* Data items */
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_PORT, expected_port);

	g_object_unref (connection);
}

static void
test_ping_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *detail, *file, *expected_ping, *expected_ping_exit, *expected_ping_restart;

	nmtst_test_data_unpack_detail (test_data, &detail, &file, &expected_ping, &expected_ping_exit, &expected_ping_restart);

	connection = get_basic_connection (detail, plugin, SRCDIR, file);
	g_assert (connection);

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	/* Data items */
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_PING, expected_ping);
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_PING_EXIT, expected_ping_exit);
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_PING_RESTART, expected_ping_restart);

	g_object_unref (connection);
}

static void
test_port_export (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;
	const char *detail, *file, *exported_name;

	nmtst_test_data_unpack_detail (test_data, &detail, &file, &exported_name);

	connection = get_basic_connection (detail, plugin, SRCDIR, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	path = g_build_path ("/", TMPDIR, exported_name, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL (detail, "export failed with missing error");
		else
			FAIL (detail, "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (detail, plugin, TMPDIR, exported_name);
	(void) unlink (path);
	ASSERT (reimported != NULL, detail, "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        detail, "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_tun_opts_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection ("tunopts-import", plugin, SRCDIR, "tun-opts.conf");
	ASSERT (connection != NULL, "tunopts-import", "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "tunopts-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("tunopts-import-data", s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
	_check_item ("tunopts-import-data", s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, "1300");
	_check_item ("tunopts-import-data", s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, "1200");

	g_object_unref (connection);
}

#define TUNOPTS_EXPORTED_NAME "tun-opts.ovpntest"
static void
test_tun_opts_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("tunopts-export", plugin, SRCDIR, "tun-opts.conf");
	ASSERT (connection != NULL, "tunopts-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, TUNOPTS_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("tunopts-export", "export failed with missing error");
		else
			FAIL ("tunopts-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("tunopts-export", plugin, TMPDIR, TUNOPTS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "tunopts-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "tunopts-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_proxy_http_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection ("proxy-http-import", plugin, SRCDIR, "proxy-http.ovpn");
	ASSERT (connection != NULL, "proxy-http-import", "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "proxy-http-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "8080");
	_check_item ("proxy-http-import-data", s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret ("proxy-http-import-secrets", s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

#define PROXY_HTTP_EXPORTED_NAME "proxy-http.ovpntest"
static void
test_proxy_http_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("proxy-http-export", plugin, SRCDIR, "proxy-http.ovpn");
	ASSERT (connection != NULL, "proxy-http-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, PROXY_HTTP_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("proxy-http-export", "export failed with missing error");
		else
			FAIL ("proxy-http-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("proxy-http-export", plugin, TMPDIR, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);
	ASSERT (reimported != NULL, "proxy-http-export", "failed to re-import connection");

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "proxy-http-export", "original and reimported connection differ");

	/* Unlink the proxy authfile */
	path = g_strdup_printf ("%s/%s-httpauthfile", TMPDIR, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);

	g_object_unref (reimported);
	g_object_unref (connection);
}

static void
test_proxy_http_with_auth_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection ("proxy-http-with-auth-import", plugin, SRCDIR, "proxy-http-with-auth.ovpn");
	ASSERT (connection != NULL, "proxy-http-with-auth-import", "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "proxy-http-with-auth-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "proxy.domain.tld");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "3128");
	_check_item ("proxy-http-with-auth-import-data", s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret ("proxy-http-with-auth-import-secrets", s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

static void
test_proxy_socks_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection ("proxy-socks-import", plugin, SRCDIR, "proxy-socks.ovpn");
	ASSERT (connection != NULL, "proxy-socks-import", "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "proxy-socks-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "socks");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item ("proxy-socks-import-data", s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "1080");

	g_object_unref (connection);
}

#define PROXY_SOCKS_EXPORTED_NAME "proxy-socks.ovpntest"
static void
test_proxy_socks_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("proxy-socks-export", plugin, SRCDIR, "proxy-socks.ovpn");
	ASSERT (connection != NULL, "proxy-socks-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, PROXY_SOCKS_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("proxy-socks-export", "export failed with missing error");
		else
			FAIL ("proxy-socks-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("proxy-socks-export", plugin, TMPDIR, PROXY_SOCKS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "proxy-socks-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "proxy-socks-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_keysize_import (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection ("keysize-import", plugin, SRCDIR, "keysize.ovpn");
	ASSERT (connection != NULL, "keysize-import", "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL,
	        "keysize-import", "missing 'vpn' setting");

	/* Data items */
	_check_item ("keysize-import-data", s_vpn, NM_OPENVPN_KEY_KEYSIZE, "512");

	g_object_unref (connection);
}

#define KEYSIZE_EXPORTED_NAME "keysize.ovpntest"
static void
test_keysize_export (void)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("keysize-export", plugin, SRCDIR, "keysize.ovpn");
	ASSERT (connection != NULL, "keysize-export", "failed to import connection");

	path = g_build_path ("/", TMPDIR, KEYSIZE_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("keysize-export", "export failed with missing error");
		else
			FAIL ("keysize-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("keysize-export", plugin, TMPDIR, KEYSIZE_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "keysize-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "keysize-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_device_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	const char *detail, *file, *expected_dev, *expected_devtype;

	nmtst_test_data_unpack_detail (test_data, &detail, &file, &expected_dev, &expected_devtype);

	connection = get_basic_connection (detail, plugin, SRCDIR, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL, detail, "missing 'vpn' setting");

	/* Data items */
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_DEV, expected_dev);
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_DEV_TYPE, expected_devtype);

	g_object_unref (connection);
}

static void
test_device_export (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;
	const char *detail, *file, *exported_name;

	nmtst_test_data_unpack_detail (test_data, &detail, &file, &exported_name);

	connection = get_basic_connection (detail, plugin, SRCDIR, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	path = g_build_path ("/", TMPDIR, exported_name, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL (detail, "export failed with missing error");
		else
			FAIL (detail, "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (detail, plugin, TMPDIR, exported_name);
	(void) unlink (path);
	ASSERT (reimported != NULL, detail, "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        detail, "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_route_import (void)
{
	_CREATE_PLUGIN (plugin);
	_CREATE_DETAIL (detail);
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	int num_routes;
	const char *expected_dest1 = "1.2.3.0";
	guint32 expected_prefix1   = 24;
	const char *expected_nh1   = "1.2.3.254";
	gint64 expected_metric1    = 99;
	const char *expected_dest2 = "5.6.7.8";
	guint32 expected_prefix2   = 30;
	const char *expected_nh2   = "0.0.0.0";
	gint64 expected_metric2    = -1;
	const char *expected_dest3 = "192.168.0.0";
	guint32 expected_prefix3   = 16;
	const char *expected_nh3   = "192.168.44.1";
	gint64 expected_metric3    = -1;

	connection = get_basic_connection (detail, plugin, SRCDIR, "route.ovpn");
	ASSERT (connection != NULL, detail, "failed to import connection");

	/* Connection setting */
	s_con = nm_connection_get_setting_connection (connection);
	ASSERT (s_con != NULL, detail, "missing 'connection' setting");

	/* VPN setting */
	s_vpn = nm_connection_get_setting_vpn (connection);
	ASSERT (s_vpn != NULL, detail, "missing 'vpn' setting");

	/* Data items */
	_check_item (detail, s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);

	/* IP4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	ASSERT (s_ip4 != NULL, detail, "missing 'ip4-config' setting");
#ifdef NM_OPENVPN_OLD
	{
		NMIP4Route *route;

#define METR(metr) ((metr) == -1 ? 0 : ((guint32) (metr)))

		num_routes = nm_setting_ip4_config_get_num_routes (s_ip4);
		ASSERT (num_routes == 3, detail, "incorrect number of static routes");

		/* route 1 */
		route = nm_setting_ip4_config_get_route (s_ip4, 0);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest1));
		ASSERT (nm_ip4_route_get_prefix (route) == expected_prefix1,
		        detail, "unexpected prefix of 1. route");
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh1));
		ASSERT (nm_ip4_route_get_metric (route) == METR (expected_metric1),
		        detail, "unexpected metric of 1. route");

		/* route 2 */
		route = nm_setting_ip4_config_get_route (s_ip4, 1);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest2));
		ASSERT (nm_ip4_route_get_prefix (route) == expected_prefix2,
		        detail, "unexpected prefix of 2. route");
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh2));
		ASSERT (nm_ip4_route_get_metric (route) == METR (expected_metric2),
		        detail, "unexpected metric of 2. route");

		/* route 3 */
		route = nm_setting_ip4_config_get_route (s_ip4, 2);
		g_assert_cmpint (nm_ip4_route_get_dest (route), ==, nmtst_inet4_from_string (expected_dest3));
		ASSERT (nm_ip4_route_get_prefix (route) == expected_prefix3,
		        detail, "unexpected prefix of 3. route");
		g_assert_cmpint (nm_ip4_route_get_next_hop (route), ==, nmtst_inet4_from_string (expected_nh3));
		ASSERT (nm_ip4_route_get_metric (route) == METR (expected_metric3),
		        detail, "unexpected metric of 3. route");
	}
#else
	{
		NMIPRoute *route;

		num_routes = nm_setting_ip_config_get_num_routes (s_ip4);
		ASSERT (num_routes == 3, detail, "incorrect number of static routes");

		/* route 1 */
		route = nm_setting_ip_config_get_route (s_ip4, 0);
		ASSERT (g_strcmp0 (nm_ip_route_get_dest (route), expected_dest1) == 0,
		        detail, "unexpected dest of 1. route");
		ASSERT (nm_ip_route_get_prefix (route) == expected_prefix1,
		        detail, "unexpected prefix of 1. route");
		ASSERT (g_strcmp0 (nm_ip_route_get_next_hop (route), expected_nh1) == 0,
		        detail, "unexpected next_hop of 1. route");
		ASSERT (nm_ip_route_get_metric (route) == expected_metric1,
		        detail, "unexpected metric of 1. route");

		/* route 2 */
		route = nm_setting_ip_config_get_route (s_ip4, 1);
		ASSERT (g_strcmp0 (nm_ip_route_get_dest (route), expected_dest2) == 0,
		        detail, "unexpected dest of 2. route");
		ASSERT (nm_ip_route_get_prefix (route) == expected_prefix2,
		        detail, "unexpected prefix of 2. route");
		ASSERT (   nm_ip_route_get_next_hop (route) == NULL
		        || g_strcmp0 (nm_ip_route_get_next_hop (route), expected_nh2) == 0,
		        detail, "unexpected next_hop of 2. route");
		ASSERT (nm_ip_route_get_metric (route) == expected_metric2,
		        detail, "unexpected metric of 2. route");

		/* route 3 */
		route = nm_setting_ip_config_get_route (s_ip4, 2);
		ASSERT (g_strcmp0 (nm_ip_route_get_dest (route), expected_dest3) == 0,
		        detail, "unexpected dest of 3. route");
		ASSERT (nm_ip_route_get_prefix (route) == expected_prefix3,
		        detail, "unexpected prefix of 3. route");
		ASSERT (g_strcmp0 (nm_ip_route_get_next_hop (route), expected_nh3) == 0,
		        detail, "unexpected next_hop of 3. route");
		ASSERT (nm_ip_route_get_metric (route) == expected_metric3,
		        detail, "unexpected metric of 3. route");
	}
#endif

	g_object_unref (connection);
}

#define ROUTE_EXPORTED_NAME "route.ovpntest"
static void
test_route_export (void)
{
	_CREATE_PLUGIN (plugin);
	_CREATE_DETAIL (detail);
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection (detail, plugin, SRCDIR, "route.ovpn");
	ASSERT (connection != NULL, detail, "failed to import connection");

	path = g_build_path ("/", TMPDIR, ROUTE_EXPORTED_NAME, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL (detail, "export failed with missing error");
		else
			FAIL (detail, "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (detail, plugin, TMPDIR, ROUTE_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, detail, "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        detail, "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

/*****************************************************************************/

static void
do_test_args_parse_impl (const char *line,
                         gboolean expects_success,
                         ...)
{
	va_list ap;
	guint i;
	const char *s;
	const char *expected_str[100] = { NULL };
	gboolean again = TRUE;
	gs_free char *line_again = NULL;
	gsize len;

	va_start (ap, expects_success);
	i = 0;
	do {
		s = va_arg (ap, const char *);
		g_assert (i < G_N_ELEMENTS (expected_str));
		expected_str[i++] = s;
	} while (s);
	va_end (ap);

	len = strlen (line);

do_again:
	{
		gs_free const char **p = NULL;
		gs_free char *line_error = NULL;

		if (!_nmovpn_test_args_parse_line (line, len, &p, &line_error)) {
			g_assert (!expects_success);
			g_assert (line_error && line_error[0]);
			g_assert (!p);
		} else {
			g_assert (expects_success);
			g_assert (!line_error);

			if (expected_str[0] == NULL) {
				g_assert (!p);
			} else {
				g_assert (p);
				for (i = 0; TRUE; i++) {
					g_assert_cmpstr (p[i], ==, expected_str[i]);
					if (expected_str[i] == NULL)
						break;
					if (i > 0)
						g_assert (p[i] == &((p[i - 1])[strlen (p[i - 1]) + 1]));
				}
				g_assert (p[0] == (const char *) (&p[i + 1]));
			}
		}
	}

	if (again) {
		/* append some gibberish. Ensure it's ignored. */
		line = line_again = g_strconcat (line, "X", NULL);
		again = FALSE;
		goto do_again;
	}
}
#define do_test_args_parse_line(...) do_test_args_parse_impl (__VA_ARGS__, NULL)

static void
test_args_parse_line (void)
{
	do_test_args_parse_line ("", TRUE);
	do_test_args_parse_line ("  ", TRUE);
	do_test_args_parse_line (" \t", TRUE);
	do_test_args_parse_line (" \r", TRUE);
	do_test_args_parse_line ("a", TRUE, "a");
	do_test_args_parse_line (" ba ", TRUE, "ba");
	do_test_args_parse_line (" b  a ", TRUE, "b", "a");
	do_test_args_parse_line (" b \\ \\a ", TRUE, "b", " a");
	do_test_args_parse_line ("\\ b \\ \\a ", TRUE, " b", " a");
	do_test_args_parse_line ("'\\ b \\ \\a '", TRUE, "\\ b \\ \\a ");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a'b'", TRUE, " b  a ab");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'", TRUE, " b  a a b");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\ \t", TRUE, " b  a a b", "sd ");

	do_test_args_parse_line ("\"adfdaf  adf  ", FALSE);
	do_test_args_parse_line ("\"adfdaf  adf  \\\"", FALSE);
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\", FALSE);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	_nmovpn_test_temp_path = TMPDIR;

	nmtst_init (&argc, &argv, TRUE);

#define _add_test_func_simple(func)       g_test_add_func ("/ovpn/properties/" #func, func)
#define _add_test_func(detail, func, ...) nmtst_add_test_func ("/ovpn/properties/" detail, detail, func, ##__VA_ARGS__)

	_add_test_func_simple (test_password_import);
	_add_test_func_simple (test_password_export);

	_add_test_func_simple (test_tls_import);
	_add_test_func_simple (test_tls_inline_import);
	_add_test_func_simple (test_tls_export);

	_add_test_func_simple (test_pkcs12_import);
	_add_test_func_simple (test_pkcs12_export);

	_add_test_func_simple (test_non_utf8_import);

	_add_test_func_simple (test_static_key_import);
	_add_test_func_simple (test_static_key_export);

	_add_test_func ("port-import", test_port_import, "port.ovpn", "port", "2345");
	_add_test_func ("port-export", test_port_export, "port.ovpn", "port.ovpntest");

	_add_test_func ("rport-import", test_port_import, "rport.ovpn", "rport", "6789");
	_add_test_func ("rport-export", test_port_export, "rport.ovpn", "rport.ovpntest");

	_add_test_func_simple (test_tun_opts_import);
	_add_test_func_simple (test_tun_opts_export);

	_add_test_func ("ping-with-exit-import", test_ping_import, "ping-with-exit.ovpn", "10", "120", NULL);
	_add_test_func ("ping-with-restart-import", test_ping_import, "ping-with-restart.ovpn", "10", NULL, "30");

	_add_test_func ("ping-with-exit-export", test_port_export, "ping-with-exit.ovpn", "ping-with-exit.ovpntest");
	_add_test_func ("ping-with-restart-export", test_port_export, "ping-with-restart.ovpn", "ping-with-restart.ovpntest");

	_add_test_func ("keepalive-import", test_ping_import, "keepalive.ovpn", "10", NULL, "30");
	_add_test_func ("keepalive-export", test_port_export, "keepalive.ovpn", "keepalive.ovpntest");

	_add_test_func_simple (test_proxy_http_import);
	_add_test_func_simple (test_proxy_http_export);

	_add_test_func_simple (test_proxy_http_with_auth_import);

	_add_test_func_simple (test_proxy_socks_import);
	_add_test_func_simple (test_proxy_socks_export);

	_add_test_func_simple (test_keysize_import);
	_add_test_func_simple (test_keysize_export);

	_add_test_func ("device-import-default", test_device_import, "device.ovpn", "company0", "tun");
	_add_test_func ("device-export-default", test_device_export, "device.ovpn", "device.ovpntest");

	_add_test_func ("device-import-notype", test_device_import, "device-notype.ovpn", "tap", NULL);
	_add_test_func ("device-export-notype", test_device_export, "device-notype.ovpn", "device-notype.ovpntest");

	_add_test_func_simple (test_route_import);
	_add_test_func_simple (test_route_export);

	_add_test_func_simple (test_args_parse_line);

	return g_test_run ();
}

