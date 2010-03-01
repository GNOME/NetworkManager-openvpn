/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
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
 * Copyright (C) 2008 - 2009 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

#include <glib/gi18n-lib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-openvpn.h"
#include "../src/nm-openvpn-service.h"

#define CLIENT_TAG "client"
#define TLS_CLIENT_TAG "tls-client"
#define DEV_TAG "dev "
#define PROTO_TAG "proto "
#define REMOTE_TAG "remote "
#define CA_TAG "ca"
#define CERT_TAG "cert"
#define KEY_TAG "key"
#define CIPHER_TAG "cipher"
#define COMP_TAG "comp-lzo"
#define IFCONFIG_TAG "ifconfig "
#define SECRET_TAG "secret"
#define AUTH_USER_PASS_TAG "auth-user-pass"
#define TLS_AUTH_TAG "tls-auth"
#define AUTH_TAG "auth "
#define RENEG_SEC_TAG "reneg-sec"
#define TLS_REMOTE_TAG "tls-remote"
#define PORT_TAG "port"
#define RPORT_TAG "rport"
#define MSSFIX_TAG "mssfix"
#define TUNMTU_TAG "tun-mtu"
#define FRAGMENT_TAG "fragment"
#define PKCS12_TAG "pkcs12"


static char *
unquote (const char *line, char **leftover)
{
	char *tmp, *item, *unquoted = NULL, *p;
	gboolean quoted = FALSE;

	if (leftover)
		g_return_val_if_fail (*leftover == NULL, FALSE);

	tmp = g_strdup (line);
	item = g_strstrip (tmp);
	if (!strlen (item)) {
		g_free (tmp);
		return NULL;
	}

	/* Simple unquote */
	if ((item[0] == '"') || (item[0] == '\'')) {
		quoted = TRUE;
		item++;
	}

	/* Unquote stuff using openvpn unquoting rules */
	unquoted = g_malloc0 (strlen (item) + 1);
	for (p = unquoted; *item; item++, p++) {
		if (quoted && ((*item == '"') || (*item == '\'')))
			break;
		else if (!quoted && isspace (*item))
			break;

		if (*item == '\\' && *(item+1) == '\\')
			*p = *(++item);
		else if (*item == '\\' && *(item+1) == '"')
			*p = *(++item);
		else if (*item == '\\' && *(item+1) == ' ')
			*p = *(++item);
		else
			*p = *item;
	}
	if (leftover && *item)
		*leftover = item + 1;

	g_free (tmp);
	return unquoted;
}


static gboolean
handle_path_item (const char *line,
                  const char *tag,
                  const char *key,
                  NMSettingVPN *s_vpn,
                  const char *path,
                  char **leftover)
{
	char *file, *full_path = NULL;

	if (strncmp (line, tag, strlen (tag)))
		return FALSE;

	file = unquote (line + strlen (tag), leftover);
	if (!file)
		return FALSE;

	/* If file isn't an absolute file name, add the default path */
	if (!g_path_is_absolute (file))
		full_path = g_build_filename (path, file, NULL);

	nm_setting_vpn_add_data_item (s_vpn, key, full_path ? full_path : file);

	g_free (file);
	g_free (full_path);
	return TRUE;
}

static char **
get_args (const char *line)
{
	char **split, **sanitized, **tmp, **tmp2;

	split = g_strsplit_set (line, " \t", 0);
	sanitized = g_malloc0 (sizeof (char *) * (g_strv_length (split) + 1));

	for (tmp = split, tmp2 = sanitized; *tmp; tmp++) {
		if (strlen (*tmp))
			*tmp2++ = g_strdup (*tmp);
	}

	g_strfreev (split);
	return sanitized;
}

static void
handle_direction (const char *tag, const char *key, char *leftover, NMSettingVPN *s_vpn)
{
	glong direction;

	if (!leftover)
		return;

	leftover = g_strstrip (leftover);
	if (!strlen (leftover))
		return;

	errno = 0;
	direction = strtol (leftover, NULL, 10);
	if (errno == 0) {
		if (direction == 0)
			nm_setting_vpn_add_data_item (s_vpn, key, "0");
		else if (direction == 1)
			nm_setting_vpn_add_data_item (s_vpn, key, "1");
	} else
		g_warning ("%s: unknown %s direction '%s'", __func__, tag, leftover);
}

static char *
parse_port (const char *str, const char *line)
{
	glong port;

	errno = 0;
	port = strtol (str, NULL, 10);
	if ((errno == 0) && (port > 0) && (port < 65536))
		return g_strdup_printf ("%d", (gint) port);

	g_warning ("%s: invalid remote port in option '%s'", __func__, line);
	return NULL;
}

NMConnection *
do_import (const char *path, char **lines, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	char *last_dot;
	char **line;
	gboolean have_client = FALSE, have_remote = FALSE;
	gboolean have_pass = FALSE, have_sk = FALSE;
	const char *ctype = NULL;
	char *basename;
	char *default_path;

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_OPENVPN, NULL);
	
	/* Get the default path for ca, cert, key file, these files maybe
	 * in same path with the configuration file */
	default_path = g_path_get_dirname (path);

	basename = g_path_get_basename (path);
	last_dot = strrchr (basename, '.');
	if (last_dot)
		*last_dot = '\0';
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, basename, NULL);
	g_free (basename);

	for (line = lines; *line; line++) {
		char *comment, **items, *leftover = NULL;

		if ((comment = strchr (*line, '#')))
			*comment = '\0';
		if ((comment = strchr (*line, ';')))
			*comment = '\0';
		if (!strlen (*line))
			continue;

		if (   !strncmp (*line, CLIENT_TAG, strlen (CLIENT_TAG))
		    || !strncmp (*line, TLS_CLIENT_TAG, strlen (TLS_CLIENT_TAG)))
			have_client = TRUE;

		if (!strncmp (*line, DEV_TAG, strlen (DEV_TAG))) {
			if (strstr (*line, "tun")) {
				/* ignore; default is tun */
			} else if (strstr (*line, "tap")) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TAP_DEV, "yes");
			} else
				g_warning ("%s: unknown dev option '%s'", __func__, *line);

			continue;
		}

		if (!strncmp (*line, PROTO_TAG, strlen (PROTO_TAG))) {
			if (strstr (*line, "udp")) {
				/* ignore; udp is default */
			} else if (strstr (*line, "tcp")) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
			} else
				g_warning ("%s: unknown proto option '%s'", __func__, *line);

			continue;
		}

		if (!strncmp (*line, MSSFIX_TAG, strlen (MSSFIX_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
			continue;
		}

		if (!strncmp (*line, TUNMTU_TAG, strlen (TUNMTU_TAG))) {
			items = get_args (*line + strlen (TUNMTU_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) >= 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					char *tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			}
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, FRAGMENT_TAG, strlen (FRAGMENT_TAG))) {
			items = get_args (*line + strlen (FRAGMENT_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) >= 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					char *tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			}
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, COMP_TAG, strlen (COMP_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
			continue;
		}

		if (!strncmp (*line, RENEG_SEC_TAG, strlen (RENEG_SEC_TAG))) {
			items = get_args (*line + strlen (RENEG_SEC_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) >= 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 604800)) {
					char *tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid time length in option '%s'", __func__, *line);
			}
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, REMOTE_TAG, strlen (REMOTE_TAG))) {
			items = get_args (*line + strlen (REMOTE_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) >= 1) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE, items[0]);
				have_remote = TRUE;

				if (g_strv_length (items) >= 2) {
					char *tmp;

					tmp = parse_port (items[1], *line);
					if (tmp) {
						nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PORT, tmp);
						g_free (tmp);
					}
				}
			}
			g_strfreev (items);

			if (!nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE))
				g_warning ("%s: unknown remote option '%s'", __func__, *line);
			continue;
		}

		if (   !strncmp (*line, PORT_TAG, strlen (PORT_TAG))
		    || !strncmp (*line, RPORT_TAG, strlen (RPORT_TAG))) {
			char *tmp;

			/* Port specified in 'remote' always takes precedence */
			if (nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PORT))
				continue;

			if (!strncmp (*line, PORT_TAG, strlen (PORT_TAG)))
				items = get_args (*line + strlen (PORT_TAG));
			else if (!strncmp (*line, RPORT_TAG, strlen (RPORT_TAG)))
				items = get_args (*line + strlen (RPORT_TAG));
			else
				g_assert_not_reached ();

			if (g_strv_length (items) >= 1) {
				tmp = parse_port (items[0], *line);
				if (tmp) {
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PORT, tmp);
					g_free (tmp);
				}
			}
		}

		if ( handle_path_item (*line, PKCS12_TAG, NM_OPENVPN_KEY_CA, s_vpn, default_path, NULL) &&
		     handle_path_item (*line, PKCS12_TAG, NM_OPENVPN_KEY_CERT, s_vpn, default_path, NULL) &&
		     handle_path_item (*line, PKCS12_TAG, NM_OPENVPN_KEY_KEY, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, CA_TAG, NM_OPENVPN_KEY_CA, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, CERT_TAG, NM_OPENVPN_KEY_CERT, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, KEY_TAG, NM_OPENVPN_KEY_KEY, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, SECRET_TAG, NM_OPENVPN_KEY_STATIC_KEY,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("secret",
			                  NM_OPENVPN_KEY_STATIC_KEY_DIRECTION,
			                  leftover,
			                  s_vpn);
			continue;
		}

		if (handle_path_item (*line, TLS_AUTH_TAG, NM_OPENVPN_KEY_TA,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("tls-auth",
			                  NM_OPENVPN_KEY_TA_DIR,
			                  leftover,
			                  s_vpn);
			continue;
		}

		if (!strncmp (*line, CIPHER_TAG, strlen (CIPHER_TAG))) {
			items = get_args (*line + strlen (CIPHER_TAG));
			if (!items)
				continue;

			if (g_strv_length (items))
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER, items[0]);

			g_strfreev (items);
			continue;
		}

		/* tls-remote */
		if (!strncmp (*line, TLS_REMOTE_TAG, strlen (TLS_REMOTE_TAG))) {
			char *unquoted = unquote (*line + strlen (TLS_REMOTE_TAG), NULL);

			if (unquoted) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, unquoted);
				g_free (unquoted);
			}
			continue;
		}

		if (!strncmp (*line, IFCONFIG_TAG, strlen (IFCONFIG_TAG))) {
			items = get_args (*line + strlen (IFCONFIG_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) == 2) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, items[0]);
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, items[1]);
			} else
				g_warning ("%s: unknown ifconfig option '%s'", __func__, *line);
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, AUTH_USER_PASS_TAG, strlen (AUTH_USER_PASS_TAG))) {
			have_pass = TRUE;
			continue;
		}

		if (!strncmp (*line, AUTH_TAG, strlen (AUTH_TAG))) {
			items = get_args (*line + strlen (AUTH_TAG));
			if (!items)
				continue;

			if (g_strv_length (items))
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_AUTH, items[0]);
			g_strfreev (items);
			continue;
		}
	}

	if (nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY))
		have_sk = TRUE;

	if (!have_client && !have_sk) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "The file to import wasn't a valid OpenVPN client configuration.");
		g_object_unref (connection);
		connection = NULL;
	} else if (!have_remote) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "The file to import wasn't a valid OpenVPN configure (no remote).");
		g_object_unref (connection);
		connection = NULL;
	} else {
		gboolean have_certs = FALSE, have_ca = FALSE;

		if (nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA))
			have_ca = TRUE;

		if (   have_ca
		    && nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT)
		    && nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY))
			have_certs = TRUE;

		/* Determine connection type */
		if (have_pass) {
			if (have_certs)
				ctype = NM_OPENVPN_CONTYPE_PASSWORD_TLS;
			else if (have_ca)
				ctype = NM_OPENVPN_CONTYPE_PASSWORD;
		} else if (have_certs) {
			ctype = NM_OPENVPN_CONTYPE_TLS;
		} else if (have_sk)
			ctype = NM_OPENVPN_CONTYPE_STATIC_KEY;

		if (!ctype)
			ctype = NM_OPENVPN_CONTYPE_TLS;

		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, ctype);
	}

	g_free (default_path);

	if (connection)
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	else if (s_vpn)
		g_object_unref (s_vpn);

	return connection;
}

gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	const char *cipher = NULL;
	const char *cacert = NULL;
	const char *connection_type = NULL;
	const char *user_cert = NULL;
	const char *private_key = NULL;
	const char *static_key = NULL;
	const char *static_key_direction = NULL;
	const char *port = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	const char *tls_remote = NULL;
	const char *tls_auth = NULL;
	const char *tls_auth_dir = NULL;
	gboolean success = FALSE;
	gboolean device_tun = TRUE;
	gboolean proto_udp = TRUE;
	gboolean use_lzo = FALSE;
	gboolean reneg_exists = FALSE;
	guint32 reneg = 0;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	f = fopen (path, "w");
	if (!f) {
		g_set_error (error, 0, 0, "could not open file for writing");
		return FALSE;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (value && strlen (value))
		connection_type = value;

	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (value && strlen (value))
			cacert = value;
	}

	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
		if (value && strlen (value))
			user_cert = value;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (value && strlen (value))
			private_key = value;
	}

	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (value && strlen (value))
			static_key = value;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
		if (value && strlen (value))
			static_key_direction = value;
	}

	/* Export tls-remote value now*/
	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE);
	if (value && strlen (value))
		tls_remote = value;

	/* Advanced values start */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PORT);
	if (value && strlen (value))
		port = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (value && strlen (value)) {
		reneg_exists = TRUE;
		reneg = strtol (value, NULL, 10);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP);
	if (value && !strcmp (value, "yes"))
		proto_udp = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TAP_DEV);
	if (value && !strcmp (value, "yes"))
		device_tun = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO);
	if (value && !strcmp (value, "yes"))
		use_lzo = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER);
	if (value && strlen (value))
		cipher = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
	if (value && strlen (value))
		local_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
	if (value && strlen (value))
		remote_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA);
	if (value && strlen (value))
		tls_auth = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR);
	if (value && strlen (value))
		tls_auth_dir = value;

	/* Advanced values end */

	fprintf (f, "client\n");
	fprintf (f, "remote %s%s%s\n",
	         gateway,
	         port ? " " : "",
	         port ? port : "");

	/* Handle PKCS#12 (all certs are the same file) */
	if (   cacert && user_cert && private_key
	    && !strcmp (cacert, user_cert) && !strcmp (cacert, private_key))
		fprintf (f, "pkcs12 %s\n", cacert);
	else {
		if (cacert)
			fprintf (f, "ca %s\n", cacert);
		if (user_cert)
			fprintf (f, "cert %s\n", user_cert);
		if (private_key)
			fprintf(f, "key %s\n", private_key);
	}

	if (   !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		fprintf (f, "auth-user-pass\n");

	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		if (static_key) {
			fprintf (f, "secret %s%s%s\n",
			         static_key,
			         static_key_direction ? " " : "",
			         static_key_direction ? static_key_direction : "");
		} else
			g_warning ("%s: invalid openvpn static key configuration (missing static key)", __func__);
	}

	if (reneg_exists)
		fprintf (f, "reneg-sec %d\n", reneg);

	if (cipher)
		fprintf (f, "cipher %s\n", cipher);

	if (use_lzo)
		fprintf (f, "comp-lzo yes\n");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX);
	if (value && strlen (value)) {
		if (!strcmp (value, "yes"))
			fprintf (f, MSSFIX_TAG "\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU);
	if (value && strlen (value))
		fprintf (f, TUNMTU_TAG " %d\n", (int) strtol (value, NULL, 10));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	if (value && strlen (value))
		fprintf (f, FRAGMENT_TAG " %d\n", (int) strtol (value, NULL, 10));

	fprintf (f, "dev %s\n", device_tun ? "tun" : "tap");
	fprintf (f, "proto %s\n", proto_udp ? "udp" : "tcp");

	if (local_ip && remote_ip)
		fprintf (f, "ifconfig %s %s\n", local_ip, remote_ip);

	if (   !strcmp(connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		if (tls_remote)
			fprintf (f,"tls-remote \"%s\"\n", tls_remote);

		if (tls_auth) {
			fprintf (f, "tls-auth %s%s%s\n",
			         tls_auth,
			         tls_auth_dir ? " " : "",
			         tls_auth_dir ? tls_auth_dir : "");
		}
	}

	/* Add hard-coded stuff */
	fprintf (f,
	         "nobind\n"
	         "auth-nocache\n"
	         "script-security 2\n"
	         "persist-key\n"
	         "persist-tun\n"
	         "user openvpn\n"
	         "group openvpn\n");
	success = TRUE;

done:
	fclose (f);
	return success;
}

