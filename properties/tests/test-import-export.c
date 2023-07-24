/*
 * network-manager-openvpn - OpenVPN integration with NetworkManager
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
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>
#include <sys/stat.h>

#include "nm-openvpn-editor-plugin.h"
#include "nm-openvpn-editor.h"
#include "import-export.h"
#include "utils.h"

#include "nm-utils/nm-test-utils.h"

#define SRCDIR TEST_SRCDIR"/conf"
#define TMPDIR TEST_BUILDDIR"/conf-tmp"

/*****************************************************************************/

static void
_test_nmovpn_remote_parse (const char *str,
                           const char *exp_host,
                           const char *exp_port,
                           const char *exp_proto)
{
	gs_free char *str_free = NULL;
	gssize r;
	const char *host, *port, *proto;
	gs_free_error GError *error = NULL;

	g_assert (exp_host || (!exp_port && !exp_proto));

	r = nmovpn_remote_parse (str, &str_free, &host, &port, &proto, &error);
	if (!exp_host) {
		g_assert (r >= 0);
		g_assert (error);
		return;
	}
	nmtst_assert_success (r == -1, error);

	g_assert_cmpstr (exp_host, ==, host);
	g_assert_cmpstr (exp_port, ==, port);
	g_assert_cmpstr (exp_proto, ==, proto);
}

static void
test_nmovpn_remote_parse (void)
{
	_test_nmovpn_remote_parse ("a",                          "a",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("a:",                         "a",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("t::",                        "t",                      NULL,    NULL);
	_test_nmovpn_remote_parse ("a::",                        "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("[a::]:",                     "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("t:::",                       "t:",                     NULL,    NULL);
	_test_nmovpn_remote_parse ("a:::",                       "a::",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("a:t::",                      "a:t",                    NULL,    NULL);
	_test_nmovpn_remote_parse ("a:b::",                      "a:b::",                  NULL,    NULL);
	_test_nmovpn_remote_parse ("a::udp",                     "a",                      NULL,    "udp");
	_test_nmovpn_remote_parse ("a:1:",                       "a",                      "1",     NULL);
	_test_nmovpn_remote_parse ("t::1:",                      "t:",                     "1",     NULL);
	_test_nmovpn_remote_parse ("t::1:",                      "t:",                     "1",     NULL);
	_test_nmovpn_remote_parse ("[a:]:1:",                    "[a:]",                   "1",     NULL);
	_test_nmovpn_remote_parse ("a::1:",                      "a::1",                   NULL,    NULL);
	_test_nmovpn_remote_parse ("a::1:1194",                  "a::1:1194",              NULL,    NULL);
	_test_nmovpn_remote_parse ("[a::1]:1194",                "a::1",                   "1194",  NULL);
	_test_nmovpn_remote_parse ("a::1194",                    "a::1194",                NULL,    NULL);
	_test_nmovpn_remote_parse ("a::1194:",                   "a::1194",                NULL,    NULL);
	_test_nmovpn_remote_parse ("[a:]:1194:",                 "[a:]",                   "1194",  NULL);
	_test_nmovpn_remote_parse ("a:1:tcp",                    "a",                      "1",     "tcp");
	_test_nmovpn_remote_parse ("aa:bb::1:1194:udp",          NULL,                     NULL,    NULL);
	_test_nmovpn_remote_parse ("[aa:bb::1]:1194:udp",        "aa:bb::1",               "1194",  "udp");
	_test_nmovpn_remote_parse ("[aa:bb::1]::udp",            "aa:bb::1",               NULL,    "udp");
	_test_nmovpn_remote_parse ("aa:bb::1::udp",              "aa:bb::1",               NULL,    "udp");
	_test_nmovpn_remote_parse ("aa:bb::1::",                 "aa:bb::1",               NULL,    NULL);
	_test_nmovpn_remote_parse ("abc.com:1234:udp",           "abc.com",                "1234",  "udp");
	_test_nmovpn_remote_parse ("ovpnserver.company.com:443", "ovpnserver.company.com", "443",   NULL);
	_test_nmovpn_remote_parse ("vpn.example.com::tcp",       "vpn.example.com",        NULL,    "tcp");
	_test_nmovpn_remote_parse ("dead:beef::1:1194",          "dead:beef::1:1194",      NULL,    NULL);
	_test_nmovpn_remote_parse ("dead:beef::1:1194",          "dead:beef::1:1194",      NULL,    NULL);
	_test_nmovpn_remote_parse ("2001:dead:beef::1194::",     "2001:dead:beef::1194",   NULL,    NULL);
}

/*****************************************************************************/

static NMVpnEditorPlugin *
_create_plugin (void)
{
	NMVpnEditorPlugin *plugin;
	GError *error = NULL;

	plugin = nm_vpn_editor_plugin_factory (&error);
	nmtst_assert_success (plugin, error);
	g_assert (OPENVPN_IS_EDITOR_PLUGIN (plugin));
	return plugin;
}
#define _CREATE_PLUGIN(plugin) \
	gs_unref_object NMVpnEditorPlugin *plugin = _create_plugin ()

/*****************************************************************************/

#define _validate_connection(connection) \
	({ \
		NMConnection *const _connection = (connection); \
		\
		g_assert (NM_IS_CONNECTION (_connection)); \
		_connection; \
	})

#define _validate_setting_connection(sett) \
	({ \
		NMSettingConnection *const _sett = (sett); \
		\
		g_assert (NM_IS_SETTING_CONNECTION (_sett)); \
		_sett; \
	})

#define _validate_setting_vpn(sett) \
	({ \
		NMSettingVpn *const _sett = (sett); \
		\
		g_assert (NM_IS_SETTING_VPN (_sett)); \
		_sett; \
	})

#define _validate_setting_ip4_config(sett) \
	({ \
		NMSettingIPConfig *const _sett = (sett); \
		\
		g_assert (NM_IS_SETTING_IP4_CONFIG (_sett)); \
		_sett; \
	})

#define _get_setting_connection(connection) \
	_validate_setting_connection (nm_connection_get_setting_connection (_validate_connection (connection)))

#define _get_setting_vpn(connection) \
	_validate_setting_vpn (nm_connection_get_setting_vpn (_validate_connection (connection)))

#define _get_setting_ip4_config(connection) \
	_validate_setting_ip4_config (nm_connection_get_setting_ip4_config (_validate_connection (connection)))

#define _check_item(s_vpn, item, expected) \
	g_assert_cmpstr (nm_setting_vpn_get_data_item (_validate_setting_vpn (s_vpn), (item)), ==, (expected))

#define _check_secret(s_vpn, item, expected) \
	g_assert_cmpstr (nm_setting_vpn_get_secret (_validate_setting_vpn (s_vpn), (item)), ==, (expected))

static NMConnection *
get_basic_connection (NMVpnEditorPlugin *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	gs_free char *pcf = NULL;

	pcf = g_build_path ("/", dir, filename, NULL);
	g_assert (pcf);

	connection = nm_vpn_editor_plugin_import (plugin, pcf, &error);
	nmtst_assert_success (connection, error);
	_validate_connection (connection);
	_get_setting_connection (connection);
	_get_setting_vpn (connection);
	return connection;
}

/*****************************************************************************/

static void
test_password_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "password.conf");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "password");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_CA, SRCDIR"/cacert.pem");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
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

	g_slist_free_full (keys, g_free);
}

static void
test_export_compare (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reimported = NULL;
	gs_free char *path = NULL;
	gboolean success;
	GError *error = NULL;
	const char *file, *exported_name;

	nmtst_test_data_unpack (test_data, &file, &exported_name);

	connection = get_basic_connection (plugin, SRCDIR, file);

	path = g_build_path ("/", TMPDIR, exported_name, NULL);
	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	nmtst_assert_success (success, error);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (plugin, TMPDIR, exported_name);
	(void) unlink (path);

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);
	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));
}

static void
test_tls_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tls.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "no-by-default");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,   SRCDIR"/keys/mg8.ca");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, SRCDIR"/keys/clee.crt");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,  SRCDIR"/keys/clee.key");
	_check_item (s_vpn, NM_OPENVPN_KEY_TA,   SRCDIR"/keys/46.key");

	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
}

static void
test_tls_import_2 (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tls2.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls2");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, "lz4");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,        SRCDIR"/keys/mg8.ca");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT,      SRCDIR"/keys/clee.crt");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,       SRCDIR"/keys/clee.key");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT, SRCDIR"/keys/46.key");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
}

static void
test_tls_import_3 (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tls3.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls3");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,        SRCDIR"/keys/mg8.ca");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT,      SRCDIR"/keys/clee.crt");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,       SRCDIR"/keys/clee.key");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT, SRCDIR"/keys/46.key");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MIN, "1.0");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MAX, "1.2");

}

static void
test_tls_import_4 (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tls4.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "tls4");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME,
	             "subject:C=US, L=Cambridge, CN=GNOME, emailAddress=networkmanager-list@gnome.org");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,           SRCDIR"/keys/mg8.ca");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT,         SRCDIR"/keys/clee.crt");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,          SRCDIR"/keys/clee.key");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT_V2, SRCDIR"/keys/46.key");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MIN, "1.0");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MIN_OR_HIGHEST, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MAX, "1.2");

}

static void
test_file_contents (const char *id,
                    const char *dir,
                    NMSettingVpn *s_vpn,
                    const char *item) {
	const char *path;
	gs_free char *path2 = NULL;
	gs_free char *contents = NULL;
	gs_free char *expected_contents = NULL;
	gsize length;
	gsize expected_length;

	path = nm_setting_vpn_get_data_item(s_vpn, item);
	g_assert (g_file_get_contents (path, &contents, &length, NULL));

	path2 = g_strdup_printf ("%s/%s-%s.pem", dir, id, item);
	g_assert (g_file_get_contents (path2, &expected_contents, &expected_length, NULL));

	g_assert_cmpmem (contents, length, expected_contents, expected_length);
}

static void
test_tls_inline_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "tls-inline";

	connection = get_basic_connection (plugin, SRCDIR, "tls-inline.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, "lz4-v2");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, "/CN=myvpn.company.com");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "server");

	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CA);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CERT);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_KEY);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_TA);
	test_file_contents (expected_id, SRCDIR, s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_FILE);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, "1");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);

	g_assert (unlink (TMPDIR"/tls-inline-ca.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-cert.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-key.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-tls-auth.pem") == 0);
	g_assert (unlink (TMPDIR"/tls-inline-crl-verify.pem") == 0);
}

static void
test_pkcs12_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "pkcs12";

	connection = get_basic_connection (plugin, SRCDIR, "pkcs12.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,   SRCDIR"/keys/mine.p12");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, SRCDIR"/keys/mine.p12");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,  SRCDIR"/keys/mine.p12");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
}

static void
test_pkcs12_with_ca_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *expected_id = "pkcs12-with-ca";

	connection = get_basic_connection (plugin, SRCDIR, "pkcs12-with-ca.ovpn");

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "173.8.149.245:1194");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_CA,   SRCDIR"/ca.crt");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, SRCDIR"/keys/mine.p12");
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY,  SRCDIR"/keys/mine.p12");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
}

static void
test_non_utf8_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *charset = NULL;

	/* Change charset to ISO-8859-15 to match iso885915.ovpn */
	g_get_charset (&charset);
	setlocale (LC_ALL, "de_DE@euro");
	connection = get_basic_connection (plugin, SRCDIR, "iso885915.ovpn");
	setlocale (LC_ALL, charset);

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "iso885915");
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CA, SRCDIR"/Att\\344taenko.pem");
}

static void
test_static_key_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *file, *expected_id, *expected_dir;

	nmtst_test_data_unpack (test_data, &file, &expected_id, &expected_dir);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);
	g_assert (!nm_setting_connection_get_uuid (s_con));

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "10.11.12.13");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, expected_dir);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, "10.8.0.2");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, "10.8.0.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);

	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, SRCDIR"/static.key");

	_check_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, NULL);
	_check_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, NULL);
}

static void
test_port_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	const char *file, *expected_id, *expected_port;

	nmtst_test_data_unpack (test_data, &file, &expected_id, &expected_port);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_con = _get_setting_connection (connection);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, expected_id);

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, expected_port);
}

static void
test_connect_timeout_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;
	const char *file, *expected_timeout;

	nmtst_test_data_unpack (test_data, &file, &expected_timeout);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECT_TIMEOUT, expected_timeout);
}

static void
test_ping_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;
	const char *file, *expected_ping, *expected_ping_exit, *expected_ping_restart;

	nmtst_test_data_unpack (test_data, &file, &expected_ping, &expected_ping_exit, &expected_ping_restart);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PING, expected_ping);
	_check_item (s_vpn, NM_OPENVPN_KEY_PING_EXIT, expected_ping_exit);
	_check_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART, expected_ping_restart);
}

static void
test_tun_opts_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "tun-opts.conf");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, "1300");
	_check_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, "1200");
}

static void
test_proxy_http_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "[aa:bb::1]:1194:udp");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "8080");
	_check_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");
}

#define PROXY_HTTP_EXPORTED_NAME "proxy-http.ovpntest"
static void
test_proxy_http_export (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reimported = NULL;
	gboolean success;
	GError *error = NULL;
	const char *path = TMPDIR"/"PROXY_HTTP_EXPORTED_NAME;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http.ovpn");

	success = nm_vpn_editor_plugin_export (plugin, path, connection, &error);
	nmtst_assert_success (success, error);

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (plugin, TMPDIR, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);

	g_assert (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT));

	/* Unlink the proxy authfile */
	(void) unlink (TMPDIR"/"PROXY_HTTP_EXPORTED_NAME"-httpauthfile");
}

static void
test_proxy_http_with_auth_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-http-with-auth.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "http");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "proxy.domain.tld");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "3128");
	_check_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, "myusername");
	_check_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, "mypassword");
}

static void
test_proxy_socks_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proxy-socks.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_PASSWORD);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, "tun");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_FLOAT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, "0");
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE, "test.server.com:443");
	_check_item (s_vpn, NM_OPENVPN_KEY_PORT, "2352");
	_check_item (s_vpn, NM_OPENVPN_KEY_CERT, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_CIPHER, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_AUTH, NULL);
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, "socks");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, "10.1.1.1");
	_check_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, "1080");
}

static void
test_keysize_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "keysize.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE, "512");
	_check_item (s_vpn, NM_OPENVPN_KEY_NCP_DISABLE, NULL);
}

static void
test_device_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;
	const char *file, *expected_dev, *expected_devtype;

	nmtst_test_data_unpack (test_data, &file, &expected_dev, &expected_devtype);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_DEV, expected_dev);
	_check_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE, expected_devtype);
}

static void
test_mtu_disc_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;
	const char *file, *expected_val;

	nmtst_test_data_unpack (test_data, &file, &expected_val);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_MTU_DISC, expected_val);
}


static void
test_crl_verify_import (gconstpointer test_data)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;
	const char *file, *expected_val;
	gpointer is_file;

	nmtst_test_data_unpack (test_data, &file, &is_file, &expected_val);

	connection = get_basic_connection (plugin, SRCDIR, file);

	s_vpn = _get_setting_vpn (connection);

	if (GPOINTER_TO_INT (is_file)) {
		_check_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_FILE, expected_val);
		_check_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_DIR, NULL);
	} else {
		_check_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_DIR, expected_val);
		_check_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_FILE, NULL);
	}
}

static void
test_route_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	NMIPRoute *route;
	int num_routes;
	const char *expected_dest1 = "1.2.3.0";
	guint32 expected_prefix1   = 24;
	const char *expected_nh1   = "1.2.3.254";
	gint64 expected_metric1    = 99;
	const char *expected_dest2 = "5.6.7.8";
	guint32 expected_prefix2   = 30;
	gint64 expected_metric2    = -1;
	const char *expected_dest3 = "192.168.0.0";
	guint32 expected_prefix3   = 16;
	const char *expected_nh3   = "192.168.44.1";
	gint64 expected_metric3    = -1;

	connection = get_basic_connection (plugin, SRCDIR, "route.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, NM_OPENVPN_CONTYPE_TLS);

	s_ip4 = _get_setting_ip4_config (connection);

	num_routes = nm_setting_ip_config_get_num_routes (s_ip4);
	g_assert_cmpint (num_routes, ==, 3);

	route = nm_setting_ip_config_get_route (s_ip4, 0);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest1);
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix1);
	g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, expected_nh1);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric1);

	route = nm_setting_ip_config_get_route (s_ip4, 1);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest2);
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix2);
	g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, NULL);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric2);

	route = nm_setting_ip_config_get_route (s_ip4, 2);
	g_assert_cmpstr (nm_ip_route_get_dest (route), ==, expected_dest3);
	g_assert_cmpint (nm_ip_route_get_prefix (route), ==, expected_prefix3);
	g_assert_cmpstr (nm_ip_route_get_next_hop (route), ==, expected_nh3);
	g_assert_cmpint (nm_ip_route_get_metric (route), ==, expected_metric3);
}

static void
test_compress_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "compress.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_ALLOW_COMPRESSION, "asym");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "adaptive");
	_check_item (s_vpn, NM_OPENVPN_KEY_COMPRESS, "lzo");
}

static void
test_push_peer_info_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "push-peer-info.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PUSH_PEER_INFO, "yes");
}

static void
test_proto_udp_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-udp.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
}

static void
test_proto_udp4_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-udp4.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
}

static void
test_proto_udp6_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-udp6.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, NULL);
}

static void
test_proto_tcp_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-tcp.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
}

static void
test_proto_tcp4_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-tcp4.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
}

static void
test_proto_tcp6_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-tcp6.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
}

static void
test_proto_tcp4_client_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-tcp4-client.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
}

static void
test_proto_tcp6_client_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "proto-tcp6-client.ovpn");

	s_vpn = nm_connection_get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
}

static void
test_data_ciphers_fallback_import (void)
{
	_CREATE_PLUGIN (plugin);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingVpn *s_vpn;

	connection = get_basic_connection (plugin, SRCDIR, "data-ciphers-fallback.ovpn");

	s_vpn = _get_setting_vpn (connection);

	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS, "AES-256-CBC");
	_check_item (s_vpn, NM_OPENVPN_KEY_DATA_CIPHERS_FALLBACK, "AES-128-CBC");
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
	do_test_args_parse_line ("\"\\ b \\ \\a \"a'b'", TRUE, " b  a ", "a'b'");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'", TRUE, " b  a ", "a 'b'");
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\ \t", TRUE, " b  a ", "a 'b'", "sd ");

	do_test_args_parse_line ("\"adfdaf  adf  ", FALSE);
	do_test_args_parse_line ("\"adfdaf  adf  \\\"", FALSE);
	do_test_args_parse_line ("\"\\ b \\ \\a \"a\\ 'b'   sd\\", FALSE);
}

/*****************************************************************************/

static void test_version(void) {
	const struct {
		guint version;
		char *const data;
		} test_data[] = {
	{
		.version = 20507,
		.data =
			"OpenVPN 2.5.7 x86_64-redhat-linux-gnu [SSL (OpenSSL)] "
			"[LZO] "
			"[LZ4] "
			"[EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 31 "
			"2022\n"
			"library versions: OpenSSL 3.0.5 5 Jul 2022, LZO 2.10\n"
			"Originally developed by James Yonan\n"
			"Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>\n"
			"Compile time defines: enable_async_push=yes "
			"enable_comp_stub=no "
			"enable_crypto_ofb_cfb=yes enable_debug=yes "
			"enable_def_auth=yes "
			"enable_dependency_tracking=no enable_dlopen=unknown "
			"enable_dlopen_self=unknown "
			"enable_dlopen_self_static=unknown "
			"enable_fast_install=needless enable_fragment=yes "
			"enable_iproute2=no "
			"enable_libtool_lock=yes enable_lz4=yes enable_lzo=yes "
			"enable_management=yes enable_multihome=yes "
			"enable_pam_dlopen=no "
			"enable_pedantic=no enable_pf=yes enable_pkcs11=yes "
			"enable_plugin_auth_pam=yes enable_plugin_down_root=yes "
			"enable_plugins=yes enable_port_share=yes "
			"enable_selinux=yes "
			"enable_shared=yes enable_shared_with_static_runtimes=no "
			"enable_silent_rules=yes enable_small=no enable_static=yes "
			"enable_strict=no enable_strict_options=no "
			"enable_systemd=yes "
			"enable_werror=no enable_win32_dll=yes "
			"enable_x509_alt_username=yes "
			"with_aix_soname=aix with_crypto_library=openssl "
			"with_gnu_ld=yes "
			"with_mem_check=no with_openssl_engine=auto "
			"with_sysroot=no\n"
			"",
		},
		{
		.version = 20310,
		.data =
			"OpenVPN 2.3.10 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] "
			"[EPOLL] [PKCS11] [MH] [IPv6] built on Jan  9 2019\n"
			"library versions: OpenSSL 1.0.2g  1 Mar 2016, LZO 2.08\n"
			"Originally developed by James Yonan\n"
			"Copyright (C) 2002-2010 OpenVPN Technologies, Inc. "
			"<sales@openvpn.net>\n"
			"Compile time defines: enable_crypto=yes "
			"enable_crypto_ofb_cfb=yes enable_debug=yes "
			"enable_def_auth=yes enable_dependency_tracking=no "
			"enable_dlopen=unknown enable_dlopen_self=unknown "
			"enable_dlopen_self_static=unknown enable_fast_install=yes "
			"enable_fragment=yes enable_http_proxy=yes "
			"enable_iproute2=yes enable_libtool_lock=yes "
			"enable_lzo=yes enable_lzo_stub=no "
			"enable_maintainer_mode=no enable_management=yes "
			"enable_multi=yes enable_multihome=yes "
			"enable_pam_dlopen=no enable_password_save=yes "
			"enable_pedantic=no enable_pf=yes enable_pkcs11=yes "
			"enable_plugin_auth_pam=yes enable_plugin_down_root=yes "
			"enable_plugins=yes enable_port_share=yes "
			"enable_selinux=no enable_server=yes enable_shared=yes "
			"enable_shared_with_static_runtimes=no "
			"enable_silent_rules=no enable_small=no enable_socks=yes "
			"enable_ssl=yes enable_static=yes enable_strict=no "
			"enable_strict_options=no enable_systemd=yes "
			"enable_win32_dll=yes enable_x509_alt_username=yes "
			"with_crypto_library=openssl with_gnu_ld=yes "
			"with_mem_check=no with_plugindir='${prefix}/lib/openvpn' "
			"with_sysroot=no\n"
			"",
		},
	};
	int i;

	for (i = 0; i < (int)G_N_ELEMENTS(test_data); i++) {
		g_assert_cmpint(test_data[i].version, ==,
		                nmovpn_version_parse(test_data[i].data));
	}

#define _test_version(v_x, v_y, v_z, encoded) \
	G_STMT_START { \
		const guint _encoded = (encoded); \
		const guint _v_x = (v_x); \
		const guint _v_y = (v_y); \
		const guint _v_z = (v_z); \
		guint _v2_x; \
		guint _v2_y; \
		guint _v2_z; \
		\
		g_assert_cmpint(nmovpn_version_encode(_v_x, _v_y, _v_z), ==, _encoded); \
		\
		nmovpn_version_decode(_encoded, &_v2_x, &_v2_y, &_v2_z); \
		g_assert_cmpint(_v_x, ==, _v2_x); \
		g_assert_cmpint(_v_y, ==, _v2_y); \
		g_assert_cmpint(_v_z, ==, _v2_z); \
	} G_STMT_END

	_test_version(1, 5, 88, 10588);
	_test_version(2, 5, 0, 20500);
	_test_version(2, 5, 4, 20504);
	_test_version(3, 0, 0, 30000);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	int errsv, result;

	_nmovpn_test_temp_path = TMPDIR;

	nmtst_init (&argc, &argv, TRUE);

	if (mkdir (TMPDIR, 0755) != 0) {
		errsv = errno;
		if (errsv != EEXIST)
			g_error ("failed creating \"%s\": %s", TMPDIR, g_strerror (errsv));
	}

#define _add_test_func_simple(func)       g_test_add_func ("/ovpn/properties/" #func, func)
#define _add_test_func(detail, func, ...) nmtst_add_test_func ("/ovpn/properties/" detail, func, ##__VA_ARGS__)

	_add_test_func_simple (test_nmovpn_remote_parse);

	_add_test_func_simple (test_password_import);
	_add_test_func ("password-export", test_export_compare, "password.conf", "password.ovpntest");

	_add_test_func_simple (test_tls_import);
	_add_test_func_simple (test_tls_inline_import);
	_add_test_func ("tls-export", test_export_compare, "tls.ovpn", "tls.ovpntest");

	_add_test_func_simple (test_tls_import_2);
	_add_test_func ("tls2-export", test_export_compare, "tls2.ovpn", "tls2.ovpntest");

	_add_test_func_simple (test_tls_import_3);
	_add_test_func ("tls3-export", test_export_compare, "tls3.ovpn", "tls3.ovpntest");

	_add_test_func_simple (test_tls_import_4);
	_add_test_func ("tls4-export", test_export_compare, "tls4.ovpn", "tls4.ovpntest");

	_add_test_func_simple (test_pkcs12_import);
	_add_test_func ("pkcs12-export", test_export_compare, "pkcs12.ovpn", "pkcs12.ovpntest");

	_add_test_func_simple (test_pkcs12_with_ca_import);
	_add_test_func ("pkcs12-with-ca-export", test_export_compare, "pkcs12-with-ca.ovpn", "pkcs12-with-ca.ovpntest");

	_add_test_func_simple (test_non_utf8_import);

	_add_test_func ("static-import-1", test_static_key_import, "static.ovpn", "static", "1");
	_add_test_func ("static-import-2", test_static_key_import, "static2.ovpn", "static2", "0");
	_add_test_func ("static", test_export_compare, "static.ovpn", "static.ovpntest");

	_add_test_func ("port-import", test_port_import, "port.ovpn", "port", "2345");
	_add_test_func ("port-export", test_export_compare, "port.ovpn", "port.ovpntest");

	_add_test_func ("rport-import", test_port_import, "rport.ovpn", "rport", "6789");
	_add_test_func ("rport-export", test_export_compare, "rport.ovpn", "rport.ovpntest");

	_add_test_func ("connect-timeout-import", test_connect_timeout_import, "connect-timeout.ovpn", "19");
	_add_test_func ("server-poll-timeout-import", test_connect_timeout_import, "server-poll-timeout.ovpn", "23");
	_add_test_func ("connect-timeout-export", test_export_compare, "connect-timeout.ovpn", "connect-timeout.ovpntest");

	_add_test_func_simple (test_tun_opts_import);
	_add_test_func ("tun-opts-export", test_export_compare, "tun-opts.conf", "tun-opts.ovpntest");

	_add_test_func ("ping-with-exit-import", test_ping_import, "ping-with-exit.ovpn", "10", "120", NULL);
	_add_test_func ("ping-with-restart-import", test_ping_import, "ping-with-restart.ovpn", "10", NULL, "30");

	_add_test_func ("ping-with-exit-export", test_export_compare, "ping-with-exit.ovpn", "ping-with-exit.ovpntest");
	_add_test_func ("ping-with-restart-export", test_export_compare, "ping-with-restart.ovpn", "ping-with-restart.ovpntest");

	_add_test_func ("keepalive-import", test_ping_import, "keepalive.ovpn", "10", NULL, "30");
	_add_test_func ("keepalive-export", test_export_compare, "keepalive.ovpn", "keepalive.ovpntest");

	_add_test_func_simple (test_proxy_http_import);
	_add_test_func_simple (test_proxy_http_export);

	_add_test_func_simple (test_proxy_http_with_auth_import);

	_add_test_func_simple (test_proxy_socks_import);
	_add_test_func ("proxy-socks-export", test_export_compare, "proxy-socks.ovpn", "proxy-socks.ovpntest");

	_add_test_func_simple (test_keysize_import);
	_add_test_func ("keysize-export", test_export_compare, "keysize.ovpn", "keysize.ovpntest");

	_add_test_func ("device-import-default", test_device_import, "device.ovpn", "company0", "tun");
	_add_test_func ("device-export-default", test_export_compare, "device.ovpn", "device.ovpntest");

	_add_test_func ("device-import-notype", test_device_import, "device-notype.ovpn", "tap", NULL);
	_add_test_func ("device-export-notype", test_export_compare, "device-notype.ovpn", "device-notype.ovpntest");

	_add_test_func ("mtu-disc-import", test_mtu_disc_import, "mtu-disc.ovpn", "yes");
	_add_test_func ("mtu-disc-export", test_export_compare, "mtu-disc.ovpn", "mtu-disc.ovpntest");

	_add_test_func ("crl-verify-file-import", test_crl_verify_import, "crl-file.ovpn", GINT_TO_POINTER (TRUE), "/home/user/.cert/crl.pem");
	_add_test_func ("crl-verify-file-export", test_export_compare, "crl-file.ovpn", "crl-file.ovpntest");

	_add_test_func ("crl-verify-dir-import", test_crl_verify_import, "crl-dir.ovpn", GINT_TO_POINTER (FALSE), "/home/user/.cert/crls/");
	_add_test_func ("crl-verify-dir-export", test_export_compare, "crl-dir.ovpn", "crl-dir.ovpntest");

	_add_test_func_simple (test_route_import);
	_add_test_func ("route-export", test_export_compare, "route.ovpn", "route.ovpntest");

	_add_test_func_simple (test_compress_import);
	_add_test_func ("compress-export", test_export_compare, "compress.ovpn", "compress.ovpntest");

	_add_test_func_simple (test_push_peer_info_import);
	_add_test_func ("push-peer-info-export", test_export_compare, "push-peer-info.ovpn", "push-peer-info.ovpntest");

	_add_test_func_simple (test_proto_udp_import);
	_add_test_func ("proto-udp-export", test_export_compare, "proto-udp.ovpn", "proto-udp.ovpntest");

	_add_test_func_simple (test_proto_udp4_import);
	_add_test_func ("proto-udp4-export", test_export_compare, "proto-udp4.ovpn", "proto-udp4.ovpntest");

	_add_test_func_simple (test_proto_udp6_import);
	_add_test_func ("proto-udp6-export", test_export_compare, "proto-udp6.ovpn", "proto-udp6.ovpntest");

	_add_test_func_simple (test_proto_tcp_import);
	_add_test_func ("proto-tcp-export", test_export_compare, "proto-tcp.ovpn", "proto-tcp.ovpntest");

	_add_test_func_simple (test_proto_tcp4_import);
	_add_test_func ("proto-tcp4-export", test_export_compare, "proto-tcp4.ovpn", "proto-tcp4.ovpntest");

	_add_test_func_simple (test_proto_tcp6_import);
	_add_test_func ("proto-tcp6-export", test_export_compare, "proto-tcp6.ovpn", "proto-tcp6.ovpntest");

	_add_test_func_simple (test_proto_tcp4_client_import);
	_add_test_func ("proto-tcp4-client-export", test_export_compare, "proto-tcp4-client.ovpn", "proto-tcp4-client.ovpntest");

	_add_test_func_simple (test_proto_tcp6_client_import);
	_add_test_func ("proto-tcp6-client-export", test_export_compare, "proto-tcp6-client.ovpn", "proto-tcp6-client.ovpntest");

	_add_test_func_simple (test_data_ciphers_fallback_import);
	_add_test_func ("data-ciphers-fallback-export", test_export_compare, "data-ciphers-fallback.ovpn", "data-ciphers-fallback.ovpntest");

	_add_test_func_simple (test_args_parse_line);

	_add_test_func_simple (test_version);

	result = g_test_run ();
	if (result != EXIT_SUCCESS)
		return result;

	if (rmdir (TMPDIR) != 0) {
		errsv = errno;
		g_error ("failed deleting %s: %s", TMPDIR, g_strerror (errsv));
	}

	return EXIT_SUCCESS;
}
