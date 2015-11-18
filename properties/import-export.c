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
 * Copyright (C) 2008 - 2013 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

#include <glib/gi18n-lib.h>

#ifdef NM_OPENVPN_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-utils.h>

#define nm_simple_connection_new nm_connection_new
#define NM_SETTING_IP_CONFIG NM_SETTING_IP4_CONFIG
#define NM_SETTING_IP_CONFIG_METHOD NM_SETTING_IP4_CONFIG_METHOD
#define NMSettingIPConfig NMSettingIP4Config

#define OPENVPN_EDITOR_PLUGIN_ERROR                     NM_SETTING_VPN_ERROR
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN    NM_SETTING_VPN_ERROR_UNKNOWN

#else /* !NM_OPENVPN_OLD */

#include <NetworkManager.h>

#define OPENVPN_EDITOR_PLUGIN_ERROR                     NM_CONNECTION_ERROR
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN    NM_CONNECTION_ERROR_FAILED
#endif

#include "import-export.h"
#include "nm-openvpn.h"
#include "../src/nm-openvpn-service-defines.h"
#include "../common/utils.h"

#define AUTH_TAG "auth "
#define AUTH_USER_PASS_TAG "auth-user-pass"
#define CA_TAG "ca "
#define CA_BLOB_START_TAG "<ca>"
#define CA_BLOB_END_TAG "</ca>"
#define CERT_TAG "cert "
#define CERT_BLOB_START_TAG "<cert>"
#define CERT_BLOB_END_TAG "</cert>"
#define CIPHER_TAG "cipher "
#define KEYSIZE_TAG "keysize "
#define CLIENT_TAG "client"
#define COMP_TAG "comp-lzo"
#define FLOAT_TAG "float"
#define DEV_TAG "dev "
#define DEV_TYPE_TAG "dev-type "
#define FRAGMENT_TAG "fragment "
#define IFCONFIG_TAG "ifconfig "
#define KEY_TAG "key "
#define KEY_BLOB_START_TAG "<key>"
#define KEY_BLOB_END_TAG "</key>"
#define KEEPALIVE_TAG "keepalive "
#define MSSFIX_TAG "mssfix"
#define PING_TAG "ping "
#define PING_EXIT_TAG "ping-exit "
#define PING_RESTART_TAG "ping-restart "
#define PKCS12_TAG "pkcs12 "
#define PORT_TAG "port "
#define PROTO_TAG "proto "
#define HTTP_PROXY_TAG "http-proxy "
#define HTTP_PROXY_RETRY_TAG "http-proxy-retry"
#define SOCKS_PROXY_TAG "socks-proxy "
#define SOCKS_PROXY_RETRY_TAG "socks-proxy-retry"
#define REMOTE_TAG "remote "
#define REMOTE_RANDOM_TAG "remote-random"
#define RENEG_SEC_TAG "reneg-sec "
#define RPORT_TAG "rport "
#define SECRET_TAG "secret "
#define TLS_AUTH_TAG "tls-auth "
#define TLS_CLIENT_TAG "tls-client"
#define TLS_REMOTE_TAG "tls-remote "
#define REMOTE_CERT_TLS_TAG "remote-cert-tls "
#define TUNMTU_TAG "tun-mtu "
#define ROUTE_TAG "route "


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
		*leftover = g_strdup (item + 1);

	g_free (tmp);
	return unquoted;
}


static gboolean
handle_path_item (const char *line,
                  const char *tag,
                  const char *key,
                  NMSettingVpn *s_vpn,
                  const char *path,
                  char **leftover)
{
	char *file, *full_path = NULL;

	if (strncmp (line, tag, strlen (tag)))
		return FALSE;

	file = unquote (line + strlen (tag), leftover);
	if (!file) {
		if (leftover) {
			g_free (*leftover);
			leftover = NULL;
		}
		return FALSE;
	}

	/* If file isn't an absolute file name, add the default path */
	if (!g_path_is_absolute (file))
		full_path = g_build_filename (path, file, NULL);

	nm_setting_vpn_add_data_item (s_vpn, key, full_path ? full_path : file);

	g_free (file);
	g_free (full_path);
	return TRUE;
}

#define CERT_BEGIN  "-----BEGIN CERTIFICATE-----"
#define CERT_END    "-----END CERTIFICATE-----"
#define PRIV_KEY_BEGIN  "-----BEGIN PRIVATE KEY-----"
#define PRIV_KEY_END    "-----END PRIVATE KEY-----"

static gboolean
handle_blob_item (const char ***line,
                  const char *key,
                  NMSettingVpn *s_vpn,
                  const char *name,
                  GError **error)
{
	gboolean success = FALSE;
	const char *blob_mark_start, *blob_mark_end;
	const char *start_tag, *end_tag;
	char *filename = NULL;
	char *dirname = NULL;
	char *path = NULL;
	GString *in_file = NULL;
	const char **p;

	if (!strcmp (key, NM_OPENVPN_KEY_CA)) {
		start_tag = CA_BLOB_START_TAG;
		end_tag = CA_BLOB_END_TAG;
		blob_mark_start = CERT_BEGIN;
		blob_mark_end = CERT_END;
	} else if (!strcmp (key, NM_OPENVPN_KEY_CERT)) {
		start_tag = CERT_BLOB_START_TAG;
		end_tag = CERT_BLOB_END_TAG;
		blob_mark_start = CERT_BEGIN;
		blob_mark_end = CERT_END;
	} else if (!strcmp (key, NM_OPENVPN_KEY_KEY)) {
		start_tag = KEY_BLOB_START_TAG;
		end_tag = KEY_BLOB_END_TAG;
		blob_mark_start = PRIV_KEY_BEGIN;
		blob_mark_end = PRIV_KEY_END;
	} else
		g_return_val_if_reached (FALSE);

	p = *line;
	if (strncmp (*p, start_tag, strlen (start_tag)))
		goto finish;
	p++;
	if (strcmp (*p, blob_mark_start))
		goto finish;
	p++;

	in_file = g_string_new (NULL);

	while (*p && strcmp (*p, blob_mark_end)) {
		g_string_append (in_file, *p);
		g_string_append_c (in_file, '\n');
		p++;
	}
	if (!*p || strncmp (*(p+1), end_tag, strlen (end_tag)))
		goto finish;
	p++;

	/* Construct file name to write the data in */
	filename = g_strdup_printf ("%s-%s.pem", name, key);
	dirname = g_build_filename (g_get_home_dir (), ".cert", NULL);
	path = g_build_filename (dirname, filename, NULL);

	/* Check that dirname exists and is a directory, otherwise create it */
	if (!g_file_test (dirname, G_FILE_TEST_IS_DIR)) {
		if (!g_file_test (dirname, G_FILE_TEST_EXISTS)) {
			if (mkdir (dirname, 0755) < 0)
				goto finish;  /* dirname could not be created */
		} else
			goto finish;  /* dirname is not a directory */
	}

	/* Write the new file */
	g_string_prepend_c (in_file, '\n');
	g_string_prepend (in_file, blob_mark_start);
	g_string_append_printf (in_file, "%s", blob_mark_end);
	success = g_file_set_contents (path, in_file->str, -1, error);
	if (!success)
		goto finish;

	nm_setting_vpn_add_data_item (s_vpn, key, path);

finish:
	line = &p;
	g_free (filename);
	g_free (dirname);
	g_free (path);
	if (in_file)
		g_string_free (in_file, TRUE);
	return success;

}

static char **
get_args (const char *line, int *nitems)
{
	char **split, **sanitized, **tmp, **tmp2;

	split = g_strsplit_set (line, " \t", 0);
	sanitized = g_malloc0 (sizeof (char *) * (g_strv_length (split) + 1));

	for (tmp = split, tmp2 = sanitized; *tmp; tmp++) {
		if (strlen (*tmp))
			*tmp2++ = g_strdup (*tmp);
	}

	g_strfreev (split);
	*nitems = g_strv_length (sanitized);

	return sanitized;
}

static void
handle_direction (const char *tag, const char *key, char *leftover, NMSettingVpn *s_vpn)
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

/* returns -1 in case of error */
static int
parse_seconds (const char *str, const char *line)
{
	glong secs;

	errno = 0;
	secs = strtol (str, NULL, 10);
	if ((errno == 0) && (secs >= 0) && (secs <= G_MAXINT))
		return (int) secs;

	g_warning ("%s: invalid number of seconds in option '%s' - must be in [0, %d]", __func__, line, G_MAXINT);
	return -1;
}

static gboolean
parse_protocol (const char *str, const char *line, gboolean *is_tcp)
{
	if (!g_strcmp0 (str, "udp")) {
		if (is_tcp)
			*is_tcp = FALSE;
		return TRUE;
	} else if (!g_strcmp0 (str, "tcp")) {
		if (is_tcp)
			*is_tcp = TRUE;
		return TRUE;
	} else {
		g_warning ("%s: invalid protocol in option '%s'", __func__, line);
		return FALSE;
	}
}

static gboolean
parse_http_proxy_auth (const char *path,
                       const char *file,
                       char **out_user,
                       char **out_pass)
{
	char *contents = NULL, *abspath = NULL, *tmp;
	GError *error = NULL;
	char **lines, **iter;

	g_return_val_if_fail (out_user != NULL, FALSE);
	g_return_val_if_fail (out_pass != NULL, FALSE);

	if (!file || !strcmp (file, "stdin") || !strcmp (file, "auto") || !strcmp (file, "'auto'"))
		return TRUE;

	if (!g_path_is_absolute (file)) {
		tmp = g_path_get_dirname (path);
		abspath = g_build_path ("/", tmp, file, NULL);
		g_free (tmp);
	} else
		abspath = g_strdup (file);

	/* Grab user/pass from authfile */
	if (!g_file_get_contents (abspath, &contents, NULL, &error)) {
		g_warning ("%s: unable to read HTTP proxy authfile '%s': (%d) %s",
		           __func__, abspath, error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		g_free (abspath);
		return FALSE;
	}

	lines = g_strsplit_set (contents, "\n\r", 0);
	for (iter = lines; iter && *iter; iter++) {
		if (!strlen (*iter))
			continue;
		if (!*out_user)
			*out_user = g_strdup (g_strstrip (*iter));
		else if (!*out_pass) {
			*out_pass = g_strdup (g_strstrip (*iter));
			break;
		}
	}
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	g_free (abspath);

	return *out_user && *out_pass;
}

static gboolean
handle_num_seconds_item (const char *line,
                         const char *tag,
                         const char *key,
                         NMSettingVpn *s_vpn)
{
	char **items = NULL;
	int nitems;

	if (!strncmp (line, tag, strlen (tag))) {
		int seconds;

		items = get_args (line + strlen (tag), &nitems);
		if (nitems == 1) {
			seconds = parse_seconds (items[0], line);
			if (seconds >= 0) {
				char *tmp;

				tmp = g_strdup_printf ("%d", seconds);
				nm_setting_vpn_add_data_item (s_vpn, key, tmp);
				g_free (tmp);
			}
		} else
			g_warning ("%s: invalid number of arguments in option '%s', must be one integer", __func__, line);

		g_strfreev (items);
		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_ip (const char *str, const char *line, guint32 *out_ip)
{
	struct in_addr ip;

	if (inet_pton (AF_INET, str, &ip) <= 0) {
		g_warning ("%s: invalid IP '%s' in option '%s'", __func__, str, line);
		return FALSE;
	}
	if (out_ip)
		*out_ip = ip.s_addr;
	return TRUE;
}

NMConnection *
do_import (const char *path, char **lines, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	char *last_dot;
	char **line;
	gboolean have_client = FALSE, have_remote = FALSE;
	gboolean have_pass = FALSE, have_sk = FALSE;
	const char *ctype = NULL;
	char *basename;
	char *default_path, *tmp, *tmp2;
	gboolean http_proxy = FALSE, socks_proxy = FALSE, proxy_set = FALSE;
	int nitems;

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENVPN, NULL);

	/* Get the default path for ca, cert, key file, these files maybe
	 * in same path with the configuration file */
	if (g_path_is_absolute (path))
		default_path = g_path_get_dirname (path);
	else {
		tmp = g_get_current_dir ();
		tmp2 = g_path_get_dirname (path);
		default_path = g_build_filename (tmp, tmp2, NULL);
		g_free (tmp);
		g_free (tmp2);
	}

	basename = g_path_get_basename (path);
	last_dot = strrchr (basename, '.');
	if (last_dot)
		*last_dot = '\0';
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, basename, NULL);

	for (line = lines; *line; line++) {
		char *comment, **items = NULL, *leftover = NULL;

		if ((comment = strchr (*line, '#')))
			*comment = '\0';
		if ((comment = strchr (*line, ';')))
			*comment = '\0';
		if (!strlen (*line))
			continue;

		if (   !strncmp (*line, CLIENT_TAG, strlen (CLIENT_TAG))
		    || !strncmp (*line, TLS_CLIENT_TAG, strlen (TLS_CLIENT_TAG))) {
			have_client = TRUE;
			continue;
		}

		if (!strncmp (*line, DEV_TAG, strlen (DEV_TAG))) {
			items = get_args (*line + strlen (DEV_TAG), &nitems);
			if (nitems == 1) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_DEV, items[0]);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, DEV_TYPE_TAG, strlen (DEV_TYPE_TAG))) {
			items = get_args (*line + strlen (DEV_TYPE_TAG), &nitems);
			if (nitems == 1) {
				if (!strcmp (items[0], "tun") || !strcmp (items[0], "tap"))
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE, items[0]);
				else
					g_warning ("%s: unknown %s option '%s'", __func__, DEV_TYPE_TAG, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, PROTO_TAG, strlen (PROTO_TAG))) {
			items = get_args (*line + strlen (PROTO_TAG), &nitems);
			if (nitems == 1) {
				/* Valid parameters are "udp", "tcp-client" and "tcp-server".
				 * 'tcp' isn't technically valid, but it used to be accepted so
				 * we'll handle it here anyway.
				 */
				if (!strcmp (items[0], "udp")) {
					/* ignore; udp is default */
				} else if (   !strcmp (items[0], "tcp-client")
				           || !strcmp (items[0], "tcp-server")
				           || !strcmp (items[0], "tcp")) {
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
				} else
					g_warning ("%s: unknown %s option '%s'", __func__, PROTO_TAG, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, MSSFIX_TAG, strlen (MSSFIX_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
			continue;
		}

		if (!strncmp (*line, TUNMTU_TAG, strlen (TUNMTU_TAG))) {
			items = get_args (*line + strlen (TUNMTU_TAG), &nitems);
			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, FRAGMENT_TAG, strlen (FRAGMENT_TAG))) {
			items = get_args (*line + strlen (FRAGMENT_TAG), &nitems);

			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, COMP_TAG, strlen (COMP_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
			continue;
		}

		if (!strncmp (*line, FLOAT_TAG, strlen (FLOAT_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
			continue;
		}

		if (!strncmp (*line, RENEG_SEC_TAG, strlen (RENEG_SEC_TAG))) {
			items = get_args (*line + strlen (RENEG_SEC_TAG), &nitems);

			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs <= 604800)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid time length in option '%s'", __func__, *line);
			}
			g_strfreev (items);
			continue;
		}

		if (   !strncmp (*line, HTTP_PROXY_RETRY_TAG, strlen (HTTP_PROXY_RETRY_TAG))
		    || !strncmp (*line, SOCKS_PROXY_RETRY_TAG, strlen (SOCKS_PROXY_RETRY_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_RETRY, "yes");
			continue;
		}

		http_proxy = g_str_has_prefix (*line, HTTP_PROXY_TAG);
		socks_proxy = g_str_has_prefix (*line, SOCKS_PROXY_TAG);
		if ((http_proxy || socks_proxy) && !proxy_set) {
			gboolean success = FALSE;
			const char *proxy_type = NULL;

			if (http_proxy) {
				items = get_args (*line + strlen (HTTP_PROXY_TAG), &nitems);
				proxy_type = "http";
			} else if (socks_proxy) {
				items = get_args (*line + strlen (SOCKS_PROXY_TAG), &nitems);
				proxy_type = "socks";
			}

			if (nitems >= 2) {
				glong port;
				char *s_port = NULL;
				char *user = NULL, *pass = NULL;

				success = TRUE;
				if (http_proxy && nitems >= 3)
					success = parse_http_proxy_auth (path, items[2], &user, &pass);

				if (success) {
					success = FALSE;
					errno = 0;
					port = strtol (items[1], NULL, 10);
					if ((errno == 0) && (port > 0) && (port < 65536)) {
						s_port = g_strdup_printf ("%d", (guint32) port);
						success = TRUE;
					}
				}

				if (success && proxy_type) {
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, proxy_type);

					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, items[0]);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, s_port);
					if (user)
						nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, user);
					if (pass) {
						nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, pass);
						nm_setting_set_secret_flags (NM_SETTING (s_vpn),
						                             NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
						                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
						                             NULL);
					}
					proxy_set = TRUE;
				}
				g_free (s_port);
				g_free (user);
				g_free (pass);
			}

			if (!success)
				g_warning ("%s: invalid proxy option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, REMOTE_TAG, strlen (REMOTE_TAG))) {
			items = get_args (*line + strlen (REMOTE_TAG), &nitems);
			if (nitems >= 1 && nitems <= 3) {
				gboolean ok = TRUE;
				tmp = NULL;

				if (nitems >= 2) {
					tmp = parse_port (items[1], *line);
					ok = tmp != NULL;
					if (ok && nitems == 3)
						ok = parse_protocol (items[2], *line, NULL);
				}
				if (ok) {
					const char *prev;
					GString *new_remote = g_string_sized_new (64);

					have_remote = TRUE;
					prev = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
					if (prev) {
						g_string_assign (new_remote, prev);
						g_string_append (new_remote, ", ");
					}
					g_string_append (new_remote, items[0]);
					if (nitems >= 2) {
						g_string_append_c (new_remote, ':');
						g_string_append (new_remote, tmp);
					}
					if (nitems == 3) {
						g_string_append_c (new_remote, ':');
						g_string_append (new_remote, items[2]);
					}
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE, new_remote->str);
					g_string_free (new_remote, TRUE);
					g_free (tmp);
				}
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, REMOTE_RANDOM_TAG, strlen (REMOTE_RANDOM_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM, "yes");
			continue;
		}

		if (   !strncmp (*line, PORT_TAG, strlen (PORT_TAG))
		    || !strncmp (*line, RPORT_TAG, strlen (RPORT_TAG))) {
			if (!strncmp (*line, PORT_TAG, strlen (PORT_TAG)))
				items = get_args (*line + strlen (PORT_TAG), &nitems);
			else if (!strncmp (*line, RPORT_TAG, strlen (RPORT_TAG)))
				items = get_args (*line + strlen (RPORT_TAG), &nitems);
			else
				g_assert_not_reached ();

			if (nitems == 1) {
				tmp = parse_port (items[0], *line);
				if (tmp) {
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PORT, tmp);
					g_free (tmp);
				}
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (handle_num_seconds_item (*line, PING_TAG, NM_OPENVPN_KEY_PING, s_vpn))
			continue;

		if (handle_num_seconds_item (*line, PING_EXIT_TAG, NM_OPENVPN_KEY_PING_EXIT, s_vpn))
			continue;

		if (handle_num_seconds_item (*line, PING_RESTART_TAG, NM_OPENVPN_KEY_PING_RESTART, s_vpn))
			continue;

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

		if (handle_blob_item ((const char ***)&line, NM_OPENVPN_KEY_CA, s_vpn, basename, NULL))
			continue;

		if (handle_blob_item ((const char ***)&line, NM_OPENVPN_KEY_CERT, s_vpn, basename, NULL))
			continue;

		if (handle_blob_item ((const char ***)&line, NM_OPENVPN_KEY_KEY, s_vpn, basename, NULL))
			continue;

		if (handle_path_item (*line, SECRET_TAG, NM_OPENVPN_KEY_STATIC_KEY,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("secret",
			                  NM_OPENVPN_KEY_STATIC_KEY_DIRECTION,
			                  leftover,
			                  s_vpn);
			g_free (leftover);
			have_sk = TRUE;
			continue;
		}

		if (handle_path_item (*line, TLS_AUTH_TAG, NM_OPENVPN_KEY_TA,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("tls-auth",
			                  NM_OPENVPN_KEY_TA_DIR,
			                  leftover,
			                  s_vpn);
			g_free (leftover);
			continue;
		}

		if (!strncmp (*line, CIPHER_TAG, strlen (CIPHER_TAG))) {
			items = get_args (*line + strlen (CIPHER_TAG), &nitems);
			if (nitems == 1)
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER, items[0]);
			else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, KEEPALIVE_TAG, strlen (KEEPALIVE_TAG))) {
			int ping_secs;
			int ping_restart_secs;

			items = get_args (*line + strlen (KEEPALIVE_TAG), &nitems);
			if (nitems == 2) {
				ping_secs = parse_seconds (items[0], *line);
				ping_restart_secs = parse_seconds (items[1], *line);

				if (ping_secs >= 0 && ping_restart_secs >= 0) {
					tmp = g_strdup_printf ("%d", ping_secs);
					tmp2 = g_strdup_printf ("%d", ping_restart_secs);

					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PING, tmp);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART, tmp2);

					g_free (tmp);
					g_free (tmp2);
				} else
					g_warning ("%s: invalid arguments in option '%s', must be two integers", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s', must be two integers", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, KEYSIZE_TAG, strlen (KEYSIZE_TAG))) {
			items = get_args (*line + strlen (KEYSIZE_TAG), &nitems);
			if (nitems == 1) {
				glong key_size;

				errno = 0;
				key_size = strtol (items[0], NULL, 10);
				if ((errno == 0) && (key_size > 0) && (key_size <= 65535)) {
					tmp = g_strdup_printf ("%d", (guint32) key_size);
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid key size in option '%s'", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, TLS_REMOTE_TAG, strlen (TLS_REMOTE_TAG))) {
			char *unquoted = unquote (*line + strlen (TLS_REMOTE_TAG), NULL);

			if (unquoted) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, unquoted);
				g_free (unquoted);
			} else
				g_warning ("%s: unknown %s option '%s'", __func__, TLS_REMOTE_TAG, *line);

			continue;
		}

		if (!strncmp (*line, REMOTE_CERT_TLS_TAG, strlen (REMOTE_CERT_TLS_TAG))) {
			items = get_args (*line + strlen (REMOTE_CERT_TLS_TAG), &nitems);
			if (nitems == 1) {
				if (   !strcmp (items[0], NM_OPENVPN_REM_CERT_TLS_CLIENT)
				    || !strcmp (items[0], NM_OPENVPN_REM_CERT_TLS_SERVER)) {
					nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, items[0]);
				} else
					g_warning ("%s: unknown %s option '%s'", __func__, REMOTE_CERT_TLS_TAG, *line);
			}

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, IFCONFIG_TAG, strlen (IFCONFIG_TAG))) {
			items = get_args (*line + strlen (IFCONFIG_TAG), &nitems);
			if (nitems == 2) {
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, items[0]);
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, items[1]);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, AUTH_USER_PASS_TAG, strlen (AUTH_USER_PASS_TAG))) {
			have_pass = TRUE;
			continue;
		}

		if (!strncmp (*line, AUTH_TAG, strlen (AUTH_TAG))) {
			items = get_args (*line + strlen (AUTH_TAG), &nitems);
			if (nitems == 1)
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_AUTH, items[0]);
			else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);
			g_strfreev (items);
			continue;
		}

#ifdef NM_OPENVPN_OLD
		if (!strncmp (*line, ROUTE_TAG, strlen (ROUTE_TAG))) {
			items = get_args (*line + strlen (ROUTE_TAG), &nitems);
			if (nitems >= 1 && nitems <= 4) {
				guint32 dest, next_hop, prefix, metric;
				NMIP4Route *route;

				if (!parse_ip (items[0], *line, &dest))
					goto route_fail;

				/* init default values */
				next_hop = 0;
				prefix = 32;
				metric = 0;
				if (nitems >= 2) {
					if (!parse_ip (items[1], *line, &prefix))
						goto route_fail;
					prefix = nm_utils_ip4_netmask_to_prefix (prefix);
					if (nitems >= 3) {
						if (!parse_ip (items[2], *line, &next_hop))
							goto route_fail;
						if (nitems == 4) {
							long num;
							errno = 0;
							num = strtol (items[3], NULL, 10);
							if ((errno == 0) && (num >= 0) && (num <= 65535))
								metric = (guint32) num;
							else {
								g_warning ("%s: invalid metric '%s' in option '%s'",
								           __func__, items[3], *line);
								goto route_fail;
							}
						}
					}
				}

				route = nm_ip4_route_new ();
				nm_ip4_route_set_dest (route, dest);
				nm_ip4_route_set_prefix (route, prefix);
				nm_ip4_route_set_next_hop (route, next_hop);
				nm_ip4_route_set_metric (route, metric);
				nm_setting_ip4_config_add_route (s_ip4, route);
				nm_ip4_route_unref (route);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

route_fail:
			g_strfreev (items);
			continue;
		}
#else
		if (!strncmp (*line, ROUTE_TAG, strlen (ROUTE_TAG))) {
			items = get_args (*line + strlen (ROUTE_TAG), &nitems);
			if (nitems >= 1 && nitems <= 4) {
				guint32 prefix = 32;
				guint32 metric = 0;
				const char *dest = items[0];
				const char *next_hop = "0.0.0.0";
				NMIPRoute *route;

				if (!parse_ip (items[0], *line, NULL))
					goto route_fail;

				if (nitems >= 2) {
					if (!parse_ip (items[1], *line, &prefix))
						goto route_fail;
					prefix = nm_utils_ip4_netmask_to_prefix (prefix);
					if (nitems >= 3) {
						if (!parse_ip (items[2], *line, NULL))
							goto route_fail;
						next_hop = items[2];
						if (nitems == 4) {
							long num;
							errno = 0;
							num = strtol (items[3], NULL, 10);
							if ((errno == 0) && (num >= 0) && (num <= 65535))
								metric = (guint32) num;
							else {
								g_warning ("%s: invalid metric '%s' in option '%s'",
								           __func__, items[3], *line);
								goto route_fail;
							}
						}
					}
				}

				route = nm_ip_route_new (AF_INET, dest, prefix, next_hop, metric, NULL);
				nm_setting_ip_config_add_route (s_ip4, route);
				nm_ip_route_unref (route);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

route_fail:
			g_strfreev (items);
			continue;
		}
#endif

	}

	if (!have_client && !have_sk) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("The file to import wasn't a valid OpenVPN client configuration."));
		g_object_unref (connection);
		connection = NULL;
	} else if (!have_remote) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("The file to import wasn't a valid OpenVPN configure (no remote)."));
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

		/* Default secret flags to be agent-owned */
		if (have_pass) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_OPENVPN_KEY_PASSWORD,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}
		if (have_certs) {
			const char *key_path;

			key_path = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
			if (key_path && is_encrypted (key_path)) {
				/* If there should be a private key password, default it to
				 * being agent-owned.
				 */
				nm_setting_set_secret_flags (NM_SETTING (s_vpn),
				                             NM_OPENVPN_KEY_CERTPASS,
				                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
				                             NULL);
			}
		}
	}

	g_free (default_path);
	g_free (basename);

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
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	FILE *f;
	const char *value;
	const char *gateways = NULL;
	char **gw_list, **gw_iter;
	const char *cipher = NULL;
	const char *cacert = NULL;
	const char *connection_type = NULL;
	const char *user_cert = NULL;
	const char *private_key = NULL;
	const char *static_key = NULL;
	const char *static_key_direction = NULL;
	const char *port = NULL;
	const char *ping = NULL;
	const char *ping_exit = NULL;
	const char *ping_restart = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	const char *tls_remote = NULL;
	const char *remote_cert_tls = NULL;
	const char *tls_auth = NULL;
	const char *tls_auth_dir = NULL;
	const char *device = NULL;
	const char *device_type = NULL;
	const char *device_default = "tun";
	gboolean success = FALSE;
	gboolean proto_udp = TRUE;
	gboolean use_lzo = FALSE;
	gboolean use_float = FALSE;
	gboolean reneg_exists = FALSE;
	guint32 reneg = 0;
	gboolean keysize_exists = FALSE;
	guint32 keysize = 0;
	gboolean randomize_hosts = FALSE;
	const char *proxy_type = NULL;
	const char *proxy_server = NULL;
	const char *proxy_port = NULL;
	const char *proxy_retry = NULL;
	const char *proxy_username = NULL;
	const char *proxy_password = NULL;
	int i;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	s_vpn = nm_connection_get_setting_vpn (connection);

	f = fopen (path, "w");
	if (!f) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("could not open file for writing"));
		return FALSE;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
	if (value && strlen (value))
		gateways = value;
	else {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("connection was incomplete (missing gateway)"));
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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING);
	if (value && strlen (value))
		ping = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_EXIT);
	if (value && strlen (value))
		ping_exit = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART);
	if (value && strlen (value))
		ping_restart = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (value && strlen (value)) {
		reneg_exists = TRUE;
		reneg = strtol (value, NULL, 10);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP);
	if (value && !strcmp (value, "yes"))
		proto_udp = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV);
	if (value && strlen (value))
		device = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE);
	if (value && strlen (value))
		device_type = value;

	/* Read legacy 'tap-dev' property for backwards compatibility. */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TAP_DEV);
	if (value && !strcmp (value, "yes"))
		device_default = "tap";

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO);
	if (value && !strcmp (value, "yes"))
		use_lzo = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FLOAT);
	if (value && !strcmp (value, "yes"))
		use_float = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER);
	if (value && strlen (value))
		cipher = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE);
	if (value && strlen (value)) {
		keysize_exists = TRUE;
		keysize = strtol (value, NULL, 10);
	}

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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	if (value && strlen (value))
		remote_cert_tls = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM);
	if (value && !strcmp (value, "yes"))
		randomize_hosts = TRUE;

	/* Advanced values end */

	fprintf (f, "client\n");

	/* 'remote' */
	gw_list = g_strsplit_set (gateways, " ,", 0);
	for (gw_iter = gw_list; gw_iter && *gw_iter; gw_iter++) {
		char *tmp_host, *tmp_port,*tmp_proto;
		if (**gw_iter == '\0')
			continue;
		tmp_host = g_strstrip (*gw_iter);
		tmp_port = strchr (tmp_host, ':');
		tmp_proto = tmp_port ? strchr (tmp_port + 1, ':') : NULL;
		if (tmp_port)
			*tmp_port++ = '\0';
		if (tmp_proto)
			*tmp_proto++ = '\0';
		if (tmp_port && !*tmp_port)
			tmp_port = NULL;
		if (tmp_proto && !*tmp_proto)
			tmp_proto = NULL;

		fprintf (f, "remote %s%s%s%s%s\n",
		         *gw_iter,
		         tmp_port ? " " : tmp_proto ? " " : "",
		         tmp_port ? tmp_port : tmp_proto ? !strcmp (tmp_proto, "udp") ? "1194" : "443": "",
		         tmp_proto ? " " : "",
		         tmp_proto ? tmp_proto : "");
	}
	g_strfreev (gw_list);

	if (randomize_hosts)
		fprintf (f, "remote-random\n");

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

	if (keysize_exists)
		fprintf (f, "keysize %d\n", keysize);

	if (use_lzo)
		fprintf (f, "comp-lzo yes\n");

	if (use_float)
		fprintf (f, "float\n");

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

	fprintf (f, "dev %s\n", device ? device : (device_type ? device_type : device_default));
	if (device_type)
		fprintf (f, "dev-type %s\n", device_type);
	fprintf (f, "proto %s\n", proto_udp ? "udp" : "tcp");
	if (port)
		fprintf (f, "port %s\n", port);

	if (ping)
		fprintf (f, "ping %s\n", ping);

	if (ping_exit)
		fprintf (f, "ping-exit %s\n", ping_exit);

	if (ping_restart)
		fprintf (f, "ping-restart %s\n", ping_restart);

	if (local_ip && remote_ip)
		fprintf (f, "ifconfig %s %s\n", local_ip, remote_ip);

	if (   !strcmp(connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		if (tls_remote)
			fprintf (f,"tls-remote \"%s\"\n", tls_remote);

		if (remote_cert_tls)
			fprintf (f,"remote-cert-tls %s\n", remote_cert_tls);

		if (tls_auth) {
			fprintf (f, "tls-auth %s%s%s\n",
			         tls_auth,
			         tls_auth_dir ? " " : "",
			         tls_auth_dir ? tls_auth_dir : "");
		}
	}

	/* Proxy stuff */
	proxy_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE);
	if (proxy_type && strlen (proxy_type)) {
		proxy_server = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER);
		proxy_port = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT);
		proxy_retry = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_RETRY);
		proxy_username = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
		proxy_password = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);

		if (!strcmp (proxy_type, "http") && proxy_server && proxy_port) {
			char *authfile, *authcontents, *base, *dirname;

			if (!proxy_port)
				proxy_port = "8080";

			/* If there's a username, need to write an authfile */
			base = g_path_get_basename (path);
			dirname = g_path_get_dirname (path);
			authfile = g_strdup_printf ("%s/%s-httpauthfile", dirname, base);
			g_free (base);
			g_free (dirname);

			fprintf (f, "http-proxy %s %s%s%s\n",
			         proxy_server,
			         proxy_port,
			         proxy_username ? " " : "",
			         proxy_username ? authfile : "");
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				fprintf (f, "http-proxy-retry\n");

			/* Write out the authfile */
			if (proxy_username) {
				authcontents = g_strdup_printf ("%s\n%s\n",
				                                proxy_username,
				                                proxy_password ? proxy_password : "");
				g_file_set_contents (authfile, authcontents, -1, NULL);
				g_free (authcontents);
			}
			g_free (authfile);
		} else if (!strcmp (proxy_type, "socks") && proxy_server && proxy_port) {
			if (!proxy_port)
				proxy_port = "1080";
			fprintf (f, "socks-proxy %s %s\n", proxy_server, proxy_port);
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				fprintf (f, "socks-proxy-retry\n");
		}
	}

#ifdef NM_OPENVPN_OLD
	/* Route handling is different in libnm-util and libnm */
	/* Static routes */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	for (i = 0; s_ip4 && i < nm_setting_ip4_config_get_num_routes (s_ip4); i++) {
		char dest_str[INET_ADDRSTRLEN];
		char netmask_str[INET_ADDRSTRLEN];
		char next_hop_str[INET_ADDRSTRLEN];
		guint32 dest, netmask, next_hop;
		NMIP4Route *route = nm_setting_ip4_config_get_route (s_ip4, i);

		dest = nm_ip4_route_get_dest (route);
		memset (dest_str, '\0', sizeof (dest_str));
		inet_ntop (AF_INET, (const void *) &dest, dest_str, sizeof (dest_str));

		memset (netmask_str, '\0', sizeof (netmask_str));
		netmask = nm_utils_ip4_prefix_to_netmask (nm_ip4_route_get_prefix (route));
		inet_ntop (AF_INET, (const void *) &netmask, netmask_str, sizeof (netmask_str));

		next_hop = nm_ip4_route_get_next_hop (route);
		memset (next_hop_str, '\0', sizeof (next_hop_str));
		inet_ntop (AF_INET, (const void *) &next_hop, next_hop_str, sizeof (next_hop_str));

		fprintf (f, "route %s %s %s %u\n",
		         dest_str,
		         netmask_str,
		         next_hop_str,
		         nm_ip4_route_get_metric (route));
	}
#else
	/* Static routes */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	for (i = 0; s_ip4 && i < nm_setting_ip_config_get_num_routes (s_ip4); i++) {
		char netmask_str[INET_ADDRSTRLEN];
		guint32 netmask;
		NMIPRoute *route = nm_setting_ip_config_get_route (s_ip4, i);

		memset (netmask_str, '\0', sizeof (netmask_str));
		netmask = nm_utils_ip4_prefix_to_netmask (nm_ip_route_get_prefix (route));
		inet_ntop (AF_INET, (const void *) &netmask, netmask_str, sizeof (netmask_str));

		fprintf (f, "route %s %s %s %ld\n",
		         nm_ip_route_get_dest (route),
		         netmask_str,
		         nm_ip_route_get_next_hop (route) ? nm_ip_route_get_next_hop (route) : "0.0.0.0",
		         nm_ip_route_get_metric (route));
	}
#endif

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

