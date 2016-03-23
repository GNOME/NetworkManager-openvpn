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

#include "config.h"

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

#include "nm-default.h"

#include "import-export.h"
#include "nm-openvpn.h"
#include "nm-openvpn-service-defines.h"
#include "utils.h"
#include "nm-macros-internal.h"
#include "nm-shared-utils.h"


#define INLINE_BLOB_CA                  "ca"
#define INLINE_BLOB_CERT                "cert"
#define INLINE_BLOB_KEY                 "key"
#define INLINE_BLOB_PKCS12              "pkcs12"
#define INLINE_BLOB_SECRET              "secret"
#define INLINE_BLOB_TLS_AUTH            "tls-auth"

#define TAG_AUTH                        "auth"
#define TAG_AUTH_USER_PASS              "auth-user-pass"
#define TAG_CA                          "ca"
#define TAG_CERT                        "cert"
#define TAG_CIPHER                      "cipher"
#define TAG_CLIENT                      "client"
#define TAG_COMP_LZO                    "comp-lzo"
#define TAG_DEV                         "dev"
#define TAG_DEV_TYPE                    "dev-type"
#define TAG_FLOAT                       "float"
#define TAG_FRAGMENT                    "fragment"
#define TAG_HTTP_PROXY                  "http-proxy"
#define TAG_HTTP_PROXY_RETRY            "http-proxy-retry"
#define TAG_IFCONFIG                    "ifconfig"
#define TAG_KEEPALIVE                   "keepalive"
#define TAG_KEY_DIRECTION               "key-direction"
#define TAG_KEY                         "key"
#define TAG_KEYSIZE                     "keysize"
#define TAG_MSSFIX                      "mssfix"
#define TAG_NOBIND                      "nobind"
#define TAG_PING_EXIT                   "ping-exit"
#define TAG_PING                        "ping"
#define TAG_PING_RESTART                "ping-restart"
#define TAG_PKCS12                      "pkcs12"
#define TAG_PORT                        "port"
#define TAG_PROTO                       "proto"
#define TAG_REMOTE_CERT_TLS             "remote-cert-tls"
#define TAG_REMOTE_RANDOM               "remote-random"
#define TAG_REMOTE                      "remote"
#define TAG_RENEG_SEC                   "reneg-sec"
#define TAG_ROUTE                       "route"
#define TAG_RPORT                       "rport"
#define TAG_SECRET                      "secret"
#define TAG_SOCKS_PROXY_RETRY           "socks-proxy-retry"
#define TAG_SOCKS_PROXY                 "socks-proxy"
#define TAG_TLS_AUTH                    "tls-auth"
#define TAG_TLS_CLIENT                  "tls-client"
#define TAG_TLS_REMOTE                  "tls-remote"
#define TAG_TOPOLOGY                    "topology"
#define TAG_TUN_MTU                     "tun-mtu"
#define TAG_TUN_IPV6                    "tun-ipv6"


const char *_nmovpn_test_temp_path = NULL;

/*****************************************************************************/

static const char *
_arg_is_set (const char *value)
{
	return (value && value[0]) ? value : NULL;
}

static void
_auto_free_gstring_p (GString **ptr)
{
	if (*ptr)
		g_string_free (*ptr, TRUE);
}

static gboolean
_is_utf8 (const char *str)
{
	g_return_val_if_fail (str, FALSE);

	return g_utf8_validate (str, -1, NULL);
}

/*****************************************************************************/

static void
__attribute__((__format__ (__printf__, 3, 4)))
setting_vpn_add_data_item_v (NMSettingVpn *setting,
                             const char *key,
                             const char *format,
                             ...)
{
	char buf[256];
	char *s;
	int l;
	va_list ap, ap2;

	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);

	/* let's first try with a stack allocated buffer,
	 * it's large enough for most cases. */
	va_start (ap, format);
	va_copy (ap2, ap);
	l = g_vsnprintf (buf, sizeof (buf), format, ap2);
	va_end (ap2);

	if (l < sizeof (buf) - 1) {
		va_end (ap);
		nm_setting_vpn_add_data_item (setting, key, buf);
		return;
	}

	s = g_strdup_vprintf (format, ap);
	va_end (ap);
	nm_setting_vpn_add_data_item (setting, key, s);
	g_free (s);
}

static void
setting_vpn_add_data_item_int64 (NMSettingVpn *setting,
                                 const char *key,
                                 gint64 value)
{
	setting_vpn_add_data_item_v (setting, key, "%"G_GINT64_FORMAT, value);
}

static void
setting_vpn_add_data_item (NMSettingVpn *setting,
                           const char *key,
                           const char *value)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);
	g_return_if_fail (value && value[0]);
	g_return_if_fail (_is_utf8 (value));

	nm_setting_vpn_add_data_item (setting, key, value);
}

static void
setting_vpn_add_data_item_utf8safe (NMSettingVpn *setting,
                                    const char *key,
                                    const char *value)
{
	gs_free char *s = NULL;

	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);
	g_return_if_fail (value && value[0]);

	nm_setting_vpn_add_data_item (setting, key,
	                              nmv_utils_str_utf8safe_escape_c (value, &s));
}

static void
setting_vpn_add_data_item_path (NMSettingVpn *setting,
                                const char *key,
                                const char *value)
{
	setting_vpn_add_data_item_utf8safe (setting, key, value);
}

static gboolean
setting_vpn_eq_data_item_utf8safe (NMSettingVpn *setting,
                                   const char *key,
                                   const char *expected_value)
{
	gs_free char *s_free = NULL;
	const char *s;

	s = nm_setting_vpn_get_data_item (setting, key);
	if (!s)
		return expected_value == NULL;

	if (!expected_value)
		return FALSE;
	return nm_streq (expected_value, nmv_utils_str_utf8safe_unescape_c (s, &s_free));
}

/*****************************************************************************/

static gboolean
args_params_check_nargs_minmax (const char **params, guint nargs_min, guint nargs_max, char **out_error)
{
	guint nargs;

	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (params[0], FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	nargs = g_strv_length ((char **) params) - 1;

	if (nargs < nargs_min || nargs > nargs_max) {
		if (nargs_min != nargs_max) {
			*out_error = g_strdup_printf (ngettext ("option %s expects between %u and %u argument",
			                                        "option %s expects between %u and %u arguments",
			                                        nargs_max),
			                              params[0], nargs_min, nargs_max);
		} else if (nargs_min == 0)
			*out_error = g_strdup_printf (_("option %s expects no arguments"), params[0]);
		else {
			*out_error = g_strdup_printf (ngettext ("option %s expects exactly one argument",
			                                        "option %s expects exactly %u arguments",
			                                         nargs_min),
			                              params[0], nargs_min);
		}
		return FALSE;
	}
	return TRUE;
}

static gboolean
args_params_check_nargs_n (const char **params, guint nargs, char **out_error)
{
	return args_params_check_nargs_minmax (params, nargs, nargs, out_error);
}

static gboolean
args_params_check_arg_nonempty (const char **params,
                                guint n_param,
                                const char *argument_name,
                                char **out_error)
{
	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (params[0], FALSE);
	g_return_val_if_fail (n_param > 0 && n_param < g_strv_length ((char **) params), FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	if (params[n_param][0] == '\0') {
		if (argument_name)
			*out_error = g_strdup_printf (_("argument %s of \"%s\" can not be empty"), argument_name, params[0]);
		else
			*out_error = g_strdup_printf (_("argument of \"%s\" can not be empty"), params[0]);
		return FALSE;
	}
	return TRUE;
}

static gboolean
args_params_check_arg_utf8 (const char **params,
                            guint n_param,
                            const char *argument_name,
                            char **out_error)
{
	if (!args_params_check_arg_nonempty (params, n_param, argument_name, out_error))
		return FALSE;
	if (!_is_utf8 (params[n_param])) {
		if (argument_name)
			*out_error = g_strdup_printf (_("argument %s of \"%s\" must be UTF-8 encoded"), argument_name, params[0]);
		else
			*out_error = g_strdup_printf (_("argument of \"%s\" must be UTF-8 encoded"), params[0]);
		return FALSE;
	}
	return TRUE;
}

static gboolean
args_params_parse_int64 (const char **params,
                         guint n_param,
                         gint64 min,
                         gint64 max,
                         gint64 *out,
                         char **out_error)
{
	gint64 v;

	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (params[0], FALSE);
	g_return_val_if_fail (n_param > 0, FALSE);
	g_return_val_if_fail (n_param < g_strv_length ((char **) params), FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	v = _nm_utils_ascii_str_to_int64 (params[n_param], 10, min, max, -1);
	if (errno) {
		*out_error = g_strdup_printf (_("invalid %uth argument to '%s' where number expected"),
		                              n_param,
		                              params[0]);
		return FALSE;
	}
	*out = v;
	return TRUE;
}

static gboolean
args_params_parse_port (const char **params, guint n_param, gint64 *out, char **out_error)
{
	return args_params_parse_int64 (params, n_param, 1, 65535, out, out_error);
}

static gboolean
args_params_parse_ip4 (const char **params,
                       guint n_param,
                       in_addr_t *out,
                       char **out_error)
{
	in_addr_t a;

	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (params[0], FALSE);
	g_return_val_if_fail (n_param > 0, FALSE);
	g_return_val_if_fail (n_param < g_strv_length ((char **) params), FALSE);
	g_return_val_if_fail (out, FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	if (inet_pton (AF_INET, params[n_param], &a) != 1) {
		*out_error = g_strdup_printf (_("invalid %uth argument to '%s' where IPv4 address expected"),
		                              n_param,
		                              params[0]);
		return FALSE;
	}
	*out = a;
	return TRUE;
}

static gboolean
args_params_parse_key_direction (const char **params,
                                 guint n_param,
                                 const char **out_key_direction,
                                 char **out_error)
{
	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (params[0], FALSE);
	g_return_val_if_fail (n_param > 0, FALSE);
	g_return_val_if_fail (n_param < g_strv_length ((char **) params), FALSE);
	g_return_val_if_fail (out_key_direction, FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	/* params will be freed in the next loop iteration. "internalize" the values. */
	if (nm_streq (params[n_param], "0"))
		*out_key_direction = "0";
	else if (nm_streq (params[n_param], "1"))
		*out_key_direction = "1";
	else {
		*out_error = g_strdup_printf (_("invalid %uth key-direction argument to '%s'"), n_param, params[0]);
		return FALSE;
	}
	return TRUE;
}

static char *
args_params_error_message_invalid_arg (const char **params, guint n_param)
{
	g_return_val_if_fail (params, NULL);
	g_return_val_if_fail (params[0], NULL);
	g_return_val_if_fail (n_param > 0, FALSE);
	g_return_val_if_fail (n_param < g_strv_length ((char **) params), FALSE);

	return g_strdup_printf (_("invalid %uth argument to '%s'"), n_param, params[0]);
}

/*****************************************************************************/

static char
_ch_step_1 (const char **str, gsize *len)
{
	char ch;
	g_assert (str);
	g_assert (len && *len > 0);

	ch = (*str)[0];

	(*str)++;
	(*len)--;
	return ch;
}

static void
_ch_skip_over_leading_whitespace (const char **str, gsize *len)
{
	while (*len > 0 && g_ascii_isspace ((*str)[0]))
		_ch_step_1 (str, len);
}

static void
_strbuf_append_c (char **buf, gsize *len, char ch)
{
	nm_assert (buf);
	nm_assert (len);

	g_return_if_fail (*len > 0);

	(*buf)[0] = ch;
	(*len)--;
	*buf = &(*buf)[1];
}

static gboolean
args_parse_line (const char *line,
                 gsize line_len,
                 const char ***out_p,
                 char **out_error)
{
	gs_unref_array GArray *index = NULL;
	gs_free char *str_buf_orig = NULL;
	char *str_buf;
	gsize str_buf_len;
	gsize i;
	const char *line_start = line;
	char **data;
	char *pdata;

	/* reimplement openvpn's parse_line(). */

	g_return_val_if_fail (line, FALSE);
	g_return_val_if_fail (out_p && !*out_p, FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	*out_p = NULL;

	/* we expect no newline during the first line_len chars. */
	for (i = 0; i < line_len; i++) {
		if (NM_IN_SET (line[i], '\0', '\n'))
			g_return_val_if_reached (FALSE);
	}

	/* if the line ends with '\r', drop that right way (covers \r\n). */
	if (line_len > 0 && line[line_len - 1] == '\r')
		line_len--;

	/* skip over leading space. */
	_ch_skip_over_leading_whitespace (&line, &line_len);

	if (line_len == 0)
		return TRUE;

	if (NM_IN_SET (line[0], ';', '#')) {
		/* comment. Note that als openvpn allows for leading spaces
		 * *before* the comment starts */
		return TRUE;
	}

	/* the maximum required buffer is @line_len+1 characters. We don't produce
	 * *more* characters then given in the input (plus trailing '\0'). */
	str_buf_len = line_len + 1;
	str_buf_orig = g_malloc (str_buf_len);
	str_buf = str_buf_orig;

	index = g_array_new (FALSE, FALSE, sizeof (gsize));

	do {
		char quote, ch0;
		gssize word_start = line - line_start;
		gsize index_i;

		index_i = str_buf - str_buf_orig;
		g_array_append_val (index, index_i);

		do {
			switch ((ch0 = _ch_step_1 (&line, &line_len))) {
			case '"':
			case '\'':
				quote = ch0;

				while (line_len > 0 && line[0] != quote) {
					if (quote == '"' && line[0] == '\\') {
						_ch_step_1 (&line, &line_len);
						if (line_len <= 0)
							break;
					}
					_strbuf_append_c (&str_buf, &str_buf_len, _ch_step_1 (&line, &line_len));
				}

				if (line_len <= 0) {
					*out_error = g_strdup_printf (_("unterminated %s at position %lld"),
					                              quote == '"' ? _("double quote") : _("single quote"),
					                              (long long) word_start);
					return FALSE;
				}

				_ch_step_1 (&line, &line_len);
				break;
			case '\\':
				if (line_len <= 0) {
					*out_error = g_strdup_printf (_("trailing escaping backslash at position %lld"),
					                              (long long) word_start);
					return FALSE;
				}
				_strbuf_append_c (&str_buf, &str_buf_len, _ch_step_1 (&line, &line_len));
				break;
			default:
				if (g_ascii_isspace (ch0))
					goto word_completed;
				_strbuf_append_c (&str_buf, &str_buf_len, ch0);
				break;
			}
		} while (line_len > 0);
word_completed:

		/* the current word is complete.*/
		_strbuf_append_c (&str_buf, &str_buf_len, '\0');
		_ch_skip_over_leading_whitespace (&line, &line_len);
	} while (line_len > 0);

	str_buf_len = str_buf - str_buf_orig;

	/* pack the result in a strv array */
	data = g_malloc ((sizeof (const char *) * (index->len + 1)) + str_buf_len);

	pdata = (char *) &data[index->len + 1];
	memcpy (pdata, str_buf_orig, str_buf_len);

	for (i = 0; i < index->len; i++)
		data[i] = &pdata[g_array_index (index, gsize, i)];
	data[i] = NULL;

	*out_p = (const char **) data;

	return TRUE;
}

gboolean
_nmovpn_test_args_parse_line (const char *line,
                              gsize line_len,
                              const char ***out_p,
                              char **out_error)
{
	return args_parse_line (line, line_len, out_p, out_error);
}

static gboolean
args_next_line (const char **content,
                gsize *content_len,
                const char **cur_line,
                gsize *cur_line_len,
                const char **cur_line_delimiter)
{
	const char *s;
	gsize l, offset;

	g_return_val_if_fail (content, FALSE);
	g_return_val_if_fail (content_len, FALSE);
	g_return_val_if_fail (cur_line, FALSE);
	g_return_val_if_fail (cur_line_len, FALSE);
	g_return_val_if_fail (cur_line_delimiter, FALSE);

	l = *content_len;

	if (l <= 0)
		return FALSE;

	*cur_line = s = *content;

	while (l > 0 && !NM_IN_SET (s[0], '\0', '\n'))
		_ch_step_1 (&s, &l);

	offset = s - *content;
	*cur_line_len = offset;

	/* cur_line_delimiter will point to a (static) string
	 * containing the dropped character.
	 * Or NULL if we reached the end of content. */
	if (l > 0) {
		if (s[0] == '\0')
			*cur_line_delimiter = "\0";
		else
			*cur_line_delimiter = "\n";
		offset++;
	} else
		*cur_line_delimiter = NULL;

	*content_len -= offset;
	*content += offset;

	return TRUE;
}

/*****************************************************************************/

static gboolean
parse_http_proxy_auth (const char *default_path,
                       const char *file,
                       char **out_user,
                       char **out_pass,
                       char **out_error)
{
	gs_free char *file_free = NULL;
	gs_free char *contents = NULL;
	char **lines, **iter;

	g_return_val_if_fail (out_user && !*out_user, FALSE);
	g_return_val_if_fail (out_pass && !*out_pass, FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	if (!file ||
	    NM_IN_STRSET (file, "stdin", "auto"))
		return TRUE;

	if (!g_path_is_absolute (file)) {
		file_free = g_build_path ("/", default_path, file, NULL);
		file = file_free;
	}

	/* Grab user/pass from authfile */
	if (!g_file_get_contents (file, &contents, NULL, NULL)) {
		*out_error = g_strdup_printf (_("unable to read HTTP proxy auth file"));
		return FALSE;
	}

	lines = g_strsplit_set (contents, "\n\r", 0);
	for (iter = lines; iter && *iter; iter++) {
		if ((*iter)[0] == '\0')
			continue;
		if (!*out_user)
			*out_user = g_strdup (g_strstrip (*iter));
		else if (!*out_pass) {
			*out_pass = g_strdup (g_strstrip (*iter));
			break;
		}
	}
	g_strfreev (lines);

	if (!*out_user || !*out_pass) {
		*out_error = g_strdup_printf (_("cannot read user/password from HTTP proxy auth file"));
		g_clear_pointer (out_user, g_free);
		g_clear_pointer (out_pass, g_free);
		return FALSE;
	}

	if (   !_is_utf8 (*out_user)
	    || !_is_utf8 (*out_pass)) {
		*out_error = g_strdup_printf (_("user/password from HTTP proxy auth file must be UTF-8 encoded"));
		g_clear_pointer (out_user, g_free);
		g_clear_pointer (out_pass, g_free);
		return FALSE;
	}
	return TRUE;
}

/*****************************************************************************/

typedef struct {
	char *token;
	char *path;
	gsize token_start_line;
	GString *blob_data;
	const char *key;
} InlineBlobData;

static void
inline_blob_data_free (InlineBlobData *data)
{
	g_return_if_fail (data);

	g_free (data->token);
	g_free (data->path);
	g_string_free (data->blob_data, TRUE);
	g_slice_free (InlineBlobData, data);
}

static char *
inline_blob_construct_path (const char *basename, const char *token)
{
	gs_free char *f_filename = NULL;

	g_return_val_if_fail (basename, NULL);
	g_return_val_if_fail (token && token[0], NULL);

	/* Construct file name to write the data in */
	f_filename = g_strdup_printf ("%s-%s.pem", basename, token);

	if (_nmovpn_test_temp_path)
		return g_build_filename (_nmovpn_test_temp_path, f_filename, NULL);

	return g_build_filename (g_get_home_dir (), ".cert/nm-openvpn", f_filename, NULL);
}

static gboolean
inline_blob_mkdir_parents (const InlineBlobData *data, const char *filepath, char **out_error)
{
	gs_free char *dirname = NULL;

	g_return_val_if_fail (filepath && filepath[0], FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	dirname = g_path_get_dirname (filepath);
	if (NM_IN_STRSET (dirname, "/", "."))
		return TRUE;

	if (g_file_test (dirname, G_FILE_TEST_IS_DIR))
		return TRUE;

	if (g_file_test (dirname, G_FILE_TEST_EXISTS)) {
		*out_error = g_strdup_printf (_("'%s' is not a directory"), dirname);
		return FALSE;
	}

	if (!inline_blob_mkdir_parents (data, dirname, out_error))
		return FALSE;

	if (mkdir (dirname, 0755) < 0) {
		*out_error = g_strdup_printf (_("cannot create '%s' directory"), dirname);
		return FALSE;
	}

	return TRUE;
}

static gboolean
inline_blob_write_out (const InlineBlobData *data, GError **error)
{
	mode_t saved_umask;

	if (!_nmovpn_test_temp_path) {
		gs_free char *err_msg = NULL;

		/* in test mode we don't create the certificate directory. */
		if (!inline_blob_mkdir_parents (data, data->path, &err_msg)) {
			g_set_error (error,
			             OPENVPN_EDITOR_PLUGIN_ERROR,
			             OPENVPN_EDITOR_PLUGIN_ERROR_FAILED,
			             _("cannot write <%s> blob from line %ld to file (%s)"),
			             data->token,
			             (long) data->token_start_line,
			             err_msg);
			return FALSE;
		}
	}

	saved_umask = umask (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	/* The file is written with the default umask. Whether that is safe enough
	 * to protect (potentally) private data or allows the openvpn service to
	 * access the file later on is left as exercise for the user. */
	if (!g_file_set_contents (data->path, data->blob_data->str, data->blob_data->len, NULL)) {
		g_set_error (error,
		             OPENVPN_EDITOR_PLUGIN_ERROR,
		             OPENVPN_EDITOR_PLUGIN_ERROR_FAILED,
		             _("cannot write <%s> blob from line %ld to file '%s'"),
		             data->token,
		             (long) data->token_start_line,
		             data->path);
		umask (saved_umask);
		return FALSE;
	}

	umask (saved_umask);
	return TRUE;
}

/*****************************************************************************/

NMConnection *
do_import (const char *path, const char *contents, gsize contents_len, GError **error)
{
	gs_unref_object NMConnection *connection_free = NULL;
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	const char *cur_line, *cur_line_delimiter;
	gsize cur_line_len;
	gsize contents_cur_line;
	gboolean have_client = FALSE, have_remote = FALSE;
	gboolean have_pass = FALSE, have_sk = FALSE;
	const char *ctype = NULL;
	gs_free char *basename = NULL;
	gs_free char *default_path = NULL;
	char *tmp, *tmp2;
	const char *last_seen_key_direction = NULL;
	gboolean have_certs, have_ca;
	GSList *inline_blobs = NULL, *sl_iter;

	g_return_val_if_fail (!error || !*error, NULL);

	connection = nm_simple_connection_new ();
	connection_free = connection;
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENVPN, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

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
	tmp = strrchr (basename, '.');
	if (tmp)
		*tmp = '\0';
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, basename, NULL);

	if (strncmp (contents, "\xEF\xBB\xBF", 3) == 0) {
		/* skip over UTF-8 BOM */
		contents += 3;
		contents_len -= 3;
	}

	contents_cur_line = 0;
	while (args_next_line (&contents,
	                       &contents_len,
	                       &cur_line,
	                       &cur_line_len,
	                       &cur_line_delimiter)) {
		gs_free const char **params = NULL;
		char *line_error = NULL;
		gint64 v_int64;

		contents_cur_line++;

		if (!args_parse_line (cur_line, cur_line_len, &params, &line_error))
			goto handle_line_error;

		if (!params) {
			/* empty line of comments. */
			continue;
		}

		g_assert (params[0]);

		/* allow for a leading double-dash and skip over it (bypass_doubledash). */
		if (g_str_has_prefix (params[0], "--"))
			params[0] = &params[0][2];

		if (NM_IN_STRSET (params[0], TAG_CLIENT, TAG_TLS_CLIENT)) {
			if (!args_params_check_nargs_n (params, 0, &line_error))
				goto handle_line_error;
			have_client = TRUE;
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_KEY_DIRECTION)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_key_direction (params, 1, &last_seen_key_direction, &line_error))
				goto handle_line_error;
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_DEV)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_nonempty (params, 1, NULL, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_utf8safe (s_vpn, NM_OPENVPN_KEY_DEV, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_DEV_TYPE)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!NM_IN_STRSET (params[1], "tun", "tap")) {
				line_error = args_params_error_message_invalid_arg (params, 1);
				goto handle_line_error;
			}
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_PROTO)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			/* Valid parameters are "udp", "tcp-client" and "tcp-server".
			 * 'tcp' isn't technically valid, but it used to be accepted so
			 * we'll handle it here anyway.
			 */
			if (nm_streq (params[1], "udp")) {
				/* ignore; udp is default */
			} else if (NM_IN_STRSET (params[1], "tcp-client", "tcp-server", "tcp"))
				setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP, "yes");
			else {
				line_error = args_params_error_message_invalid_arg (params, 1);
				goto handle_line_error;
			}
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_MSSFIX)) {
			if (!args_params_check_nargs_minmax (params, 0, 1, &line_error))
				goto handle_line_error;
			/* TODO: handle the mssfix argument. */
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_TUN_MTU)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 0, 0xffff, &v_int64, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_FRAGMENT)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 0, 0xffff, &v_int64, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_COMP_LZO)) {
			if (!args_params_check_nargs_minmax (params, 0, 1, &line_error))
				goto handle_line_error;
			if (params[1]) {
				if (nm_streq (params[1], "no"))
					continue;
				if (!nm_streq (params[1], "yes")) {
					line_error = g_strdup_printf (_("unsupported comp-lzo argument"));
					goto handle_line_error;
				}
			}
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_FLOAT)) {
			if (!args_params_check_nargs_n (params, 0, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_FLOAT, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_RENEG_SEC)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 0, 0xffff, &v_int64, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_HTTP_PROXY_RETRY, TAG_SOCKS_PROXY_RETRY)) {
			if (!args_params_check_nargs_n (params, 0, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_RETRY, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_HTTP_PROXY, TAG_SOCKS_PROXY)) {
			const char *proxy_type = NULL;
			gint64 port = 0;
			gs_free char *user = NULL;
			gs_free char *pass = NULL;

			if (NM_IN_STRSET (params[0], TAG_HTTP_PROXY)) {
				proxy_type = "http";
				if (!args_params_check_nargs_minmax (params, 2, 4, &line_error))
					goto handle_line_error;
			} else {
				proxy_type = "socks";
				if (!args_params_check_nargs_minmax (params, 1, 3, &line_error))
					goto handle_line_error;
			}

			if (!args_params_check_arg_utf8 (params, 1, "service", &line_error))
				goto handle_line_error;

			if (params[2]) {
				if (!args_params_parse_port (params, 2, &port, &line_error))
					goto handle_line_error;

				if (params[3]) {
					if (!parse_http_proxy_auth (default_path, params[3], &user, &pass, &line_error))
						goto handle_line_error;
				}
			}

			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE, proxy_type);

			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER, params[1]);
			if (port > 0)
				setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_PROXY_PORT, port);
			if (user)
				setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, user);
			if (pass) {
				nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, pass);
				nm_setting_set_secret_flags (NM_SETTING (s_vpn),
				                             NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
				                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
				                             NULL);
			}
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_REMOTE)) {
			const char *prev;
			GString *new_remote;
			int port = -1;

			if (!args_params_check_nargs_minmax (params, 1, 3, &line_error))
				goto handle_line_error;

			if (!args_params_check_arg_utf8 (params, 1, NULL, &line_error))
				goto handle_line_error;
			if (strchr (params[1], ' ')) {
				line_error = g_strdup_printf (_("remote cannot contain space"));
				goto handle_line_error;
			}
			if (strchr (params[1], ',')) {
				line_error = g_strdup_printf (_("remote cannot contain comma"));
				goto handle_line_error;
			}

			if (params[2]) {
				if (!args_params_parse_port (params, 2, &v_int64, &line_error))
					goto handle_line_error;
				port = v_int64;

				if (params[3]) {
					if (!NM_IN_STRSET (params[3], "udp", "tcp")) {
						line_error = g_strdup_printf (_("remote expects protocol either udp or remote"));
						goto handle_line_error;
					}
				}
			}

			new_remote = g_string_sized_new (64);

			prev = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
			if (prev) {
				g_string_assign (new_remote, prev);
				g_string_append (new_remote, ", ");
			}
			g_string_append (new_remote, params[1]);
			if (params[2]) {
				g_string_append_printf (new_remote, ":%d", port);
				if (params[3]) {
					g_string_append_c (new_remote, ':');
					g_string_append (new_remote, params[3]);
				}
			}
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE, new_remote->str);
			g_string_free (new_remote, TRUE);

			have_remote = TRUE;
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_REMOTE_RANDOM)) {
			if (!args_params_check_nargs_n (params, 0, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_TUN_IPV6)) {
			if (!args_params_check_nargs_n (params, 0, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TUN_IPV6, "yes");
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_PORT, TAG_RPORT)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_port (params, 1, &v_int64, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_PORT, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_PING, TAG_PING_EXIT, TAG_PING_RESTART)) {
			const char *key = NULL;

			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 0, G_MAXINT, &v_int64, &line_error))
				goto handle_line_error;

			if (NM_IN_STRSET (params[0], TAG_PING))
				key = NM_OPENVPN_KEY_PING;
			else if (NM_IN_STRSET (params[0], TAG_PING_EXIT))
				key = NM_OPENVPN_KEY_PING_EXIT;
			else if (NM_IN_STRSET (params[0], TAG_PING_RESTART))
				key = NM_OPENVPN_KEY_PING_RESTART;

			setting_vpn_add_data_item_int64 (s_vpn, key, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0],
		                 TAG_PKCS12,
		                 TAG_CA,
		                 TAG_CERT,
		                 TAG_KEY,
		                 TAG_SECRET,
		                 TAG_TLS_AUTH)) {
			const char *file;
			gs_free char *file_free = NULL;
			gboolean can_have_direction;
			const char *s_direction = NULL;

			can_have_direction = NM_IN_STRSET (params[0],
			                                  TAG_SECRET,
			                                  TAG_TLS_AUTH);

			if (!args_params_check_nargs_minmax (params, 1, can_have_direction ? 2 : 1, &line_error))
				goto handle_line_error;

			if (!args_params_check_arg_nonempty (params, 1, NULL, &line_error))
				goto handle_line_error;
			file = params[1];

			if (params[2]) {
				if (!args_params_parse_key_direction (params, 2, &s_direction, &line_error))
					goto handle_line_error;
				last_seen_key_direction = s_direction;
			}

			if (!g_path_is_absolute (file))
				file = file_free = g_build_filename (default_path, file, NULL);

			if (NM_IN_STRSET (params[0], TAG_PKCS12)) {
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CA, file);
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CERT, file);
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_KEY, file);
			} else if (NM_IN_STRSET (params[0], TAG_CA))
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CA, file);
			else if (NM_IN_STRSET (params[0], TAG_CERT))
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CERT, file);
			else if (NM_IN_STRSET (params[0], TAG_KEY))
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_KEY, file);
			else if (NM_IN_STRSET (params[0], TAG_SECRET)) {
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, file);
				if (s_direction)
					setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, s_direction);
				have_sk = TRUE;
			} else if (NM_IN_STRSET (params[0], TAG_TLS_AUTH)) {
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_TA, file);
				if (s_direction)
					setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, s_direction);
			} else
				g_assert_not_reached ();
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_CIPHER)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_utf8 (params, 1, NULL, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CIPHER, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_KEEPALIVE)) {
			gint64 v2;

			if (!args_params_check_nargs_n (params, 2, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 0, G_MAXINT, &v_int64, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 2, 0, G_MAXINT, &v2, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_PING, v_int64);
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_PING_RESTART, v2);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_KEYSIZE)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_parse_int64 (params, 1, 1, 65535, &v_int64, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item_int64 (s_vpn, NM_OPENVPN_KEY_KEYSIZE, v_int64);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_TLS_REMOTE)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_utf8 (params, 1, NULL, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_REMOTE_CERT_TLS)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!NM_IN_STRSET (params[1], NM_OPENVPN_REM_CERT_TLS_CLIENT, NM_OPENVPN_REM_CERT_TLS_SERVER)) {
				line_error = g_strdup_printf (_("invalid option"));
				goto handle_line_error;
			}
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_IFCONFIG)) {
			if (!args_params_check_nargs_n (params, 2, &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_utf8 (params, 1, "local", &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_utf8 (params, 2, "remote", &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, params[1]);
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, params[2]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_AUTH_USER_PASS)) {
			if (!args_params_check_nargs_minmax (params, 0, 1, &line_error))
				goto handle_line_error;
			have_pass = TRUE;
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_AUTH)) {
			if (!args_params_check_nargs_n (params, 1, &line_error))
				goto handle_line_error;
			if (!args_params_check_arg_utf8 (params, 1, NULL, &line_error))
				goto handle_line_error;
			setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_AUTH, params[1]);
			continue;
		}

		if (NM_IN_STRSET (params[0], TAG_ROUTE)) {
			in_addr_t network;
			in_addr_t gateway = 0;
			guint32 prefix = 32;
			gint64 metric = -1;

			if (!args_params_check_nargs_minmax (params, 1, 4, &line_error))
				goto handle_line_error;

			if (!args_params_parse_ip4 (params, 1, &network, &line_error))
				goto handle_line_error;

			if (params[2]) {
				in_addr_t netmask;

				if (!args_params_parse_ip4 (params, 2, &netmask, &line_error))
					goto handle_line_error;
				prefix = nm_utils_ip4_netmask_to_prefix (netmask);

				if (params[3]) {
					if (!args_params_parse_ip4 (params, 3, &gateway, &line_error))
						goto handle_line_error;
					if (params[4]) {
						if (!args_params_parse_int64 (params, 4, 0, G_MAXUINT32, &v_int64, &line_error))
							goto handle_line_error;
						metric = (guint32) v_int64;
					}
				}
			}

			{
#ifdef NM_OPENVPN_OLD
				NMIP4Route *route;

				route = nm_ip4_route_new ();
				nm_ip4_route_set_dest (route, network);
				nm_ip4_route_set_prefix (route, prefix);
				nm_ip4_route_set_next_hop (route, gateway);
				if (metric >= 0)
					nm_ip4_route_set_metric (route, metric);
				nm_setting_ip4_config_add_route (s_ip4, route);
				nm_ip4_route_unref (route);
#else
				NMIPRoute *route;

				route = nm_ip_route_new_binary (AF_INET, &network, prefix, params[3] ? &gateway : NULL, metric, NULL);
				nm_setting_ip_config_add_route (s_ip4, route);
				nm_ip_route_unref (route);
#endif
			}
		}

		if (params[0][0] == '<' && params[0][strlen (params[0]) - 1] == '>') {
			gs_free char *token = g_strndup (&params[0][1], strlen (params[0]) - 2);
			gs_free char *end_token = NULL;
			gsize end_token_len;
			gsize my_contents_cur_line = contents_cur_line;
			char *f_path;
			const char *key;
			gboolean can_have_direction = FALSE;
			GString *blob_data;
			InlineBlobData *inline_blob_data;

			if (nm_streq (token, INLINE_BLOB_CA))
				key = NM_OPENVPN_KEY_CA;
			else if (nm_streq (token, INLINE_BLOB_CERT))
				key = NM_OPENVPN_KEY_CERT;
			else if (nm_streq (token, INLINE_BLOB_KEY))
				key = NM_OPENVPN_KEY_KEY;
			else if (nm_streq (token, INLINE_BLOB_PKCS12))
				key = NULL;
			else if (nm_streq (token, INLINE_BLOB_TLS_AUTH)) {
				key = NM_OPENVPN_KEY_TA;
				can_have_direction = TRUE;
			} else if (nm_streq (token, INLINE_BLOB_SECRET)) {
				key = NM_OPENVPN_KEY_STATIC_KEY;
				can_have_direction = TRUE;
			} else {
				line_error = g_strdup_printf (_("unsupported blob/xml element"));
				goto handle_line_error;
			}

			end_token = g_strdup_printf ("</%s>", token);
			end_token_len = strlen (end_token);

			blob_data = g_string_new (NULL);

			while (args_next_line (&contents,
			                       &contents_len,
			                       &cur_line,
			                       &cur_line_len,
			                       &cur_line_delimiter)) {
				my_contents_cur_line++;

				/* skip over trailing space like openvpn does. */
				_ch_skip_over_leading_whitespace (&cur_line, &cur_line_len);

				if (!strncmp (cur_line, end_token, end_token_len)) {
					end_token_len = 0;
					break;
				}

				g_string_append_len (blob_data, cur_line, cur_line_len);
				if (cur_line_delimiter)
					g_string_append_c (blob_data, cur_line_delimiter[0]);
			}
			if (end_token_len) {
				line_error = g_strdup_printf (_("unterminated blob element <%s>"), token);
				g_string_free (blob_data, TRUE);
				goto handle_line_error;
			}

			/* the latest cert wins... */
			for (sl_iter = inline_blobs; sl_iter; sl_iter = sl_iter->next) {
				InlineBlobData *d = sl_iter->data;

				if (nm_streq (d->token, token)) {
					inline_blobs = g_slist_delete_link (inline_blobs, sl_iter);
					inline_blob_data_free (d);
					break;
				}
			}

			f_path = inline_blob_construct_path (basename, token);

			inline_blob_data = g_slice_new (InlineBlobData);
			inline_blob_data->blob_data = blob_data;
			inline_blob_data->token_start_line = contents_cur_line;
			inline_blob_data->path = f_path;
			inline_blob_data->token = token;
			inline_blob_data->key = key;
			token = NULL;

			inline_blobs = g_slist_prepend (inline_blobs, inline_blob_data);
			contents_cur_line = my_contents_cur_line;

			if (key)
				setting_vpn_add_data_item_path (s_vpn, key, f_path);
			else {
				nm_assert (nm_streq (token, INLINE_BLOB_PKCS12));
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CA, f_path);
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_CERT, f_path);
				setting_vpn_add_data_item_path (s_vpn, NM_OPENVPN_KEY_KEY, f_path);
			}
			if (   can_have_direction
			    && last_seen_key_direction)
				setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR, last_seen_key_direction);
			continue;
		}

		/* TODO: currently we ignore any unknown options and skip over them. */
		continue;

handle_line_error:
		g_set_error (error,
		             OPENVPN_EDITOR_PLUGIN_ERROR,
		             OPENVPN_EDITOR_PLUGIN_ERROR_FILE_INVALID,
		             _("configuration error: %s (line %ld)"),
		             line_error ? : _("unknown or unsupported option"),
		             (long) contents_cur_line);
		g_free (line_error);
		goto out_error;
	}

	if (!have_client && !have_sk) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("The file to import wasn't a valid OpenVPN client configuration"));
		goto out_error;
	}

	if (!have_remote) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("The file to import wasn't a valid OpenVPN configure (no remote)"));
		goto out_error;
	}

	have_certs = FALSE;
	have_ca = FALSE;

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

	setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, ctype);

	/* Default secret flags to be agent-owned */
	if (have_pass) {
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_OPENVPN_KEY_PASSWORD,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
	}
	if (have_certs) {
		gs_free char *key_path_free = NULL;
		const char *key_path;

		key_path = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (is_encrypted (nmv_utils_str_utf8safe_unescape_c (key_path, &key_path_free))) {
			/* If there should be a private key password, default it to
			 * being agent-owned.
			 */
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_OPENVPN_KEY_CERTPASS,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}
	}

	inline_blobs = g_slist_reverse (inline_blobs);
	for (sl_iter = inline_blobs; sl_iter; sl_iter = sl_iter->next) {
		const InlineBlobData *data = sl_iter->data;

		/* Check whether the setting was not overwritten by a later entry in the config-file. */
		if (nm_streq (data->token, INLINE_BLOB_PKCS12)) {
			if (   !setting_vpn_eq_data_item_utf8safe (s_vpn, NM_OPENVPN_KEY_CA, data->path)
			    && !setting_vpn_eq_data_item_utf8safe (s_vpn, NM_OPENVPN_KEY_CERT, data->path)
			    && !setting_vpn_eq_data_item_utf8safe (s_vpn, NM_OPENVPN_KEY_KEY, data->path))
				continue;
		} else {
			if (!setting_vpn_eq_data_item_utf8safe (s_vpn, data->key, data->path))
				continue;
		}
		if (!inline_blob_write_out (sl_iter->data, error))
			goto out_error;
	}
	g_slist_free_full (inline_blobs, (GDestroyNotify) inline_blob_data_free);

	connection_free = NULL;
	g_return_val_if_fail (!error || !*error, connection);
	return connection;

out_error:
	g_slist_free_full (inline_blobs, (GDestroyNotify) inline_blob_data_free);
	g_return_val_if_fail (!error || *error, NULL);
	return NULL;
}

/*****************************************************************************/

static const char *
escape_arg (const char *value, char **buf)
{
	const char *s;
	char *result, *i_result;
	gboolean has_single_quote = FALSE;
	gboolean needs_quotation = FALSE;
	gsize len;

	nm_assert (value);
	nm_assert (buf && !*buf);

	if (value[0] == '\0')
		return (*buf = g_strdup ("''"));

	/* check if the string contains only benign characters... */
	len = 0;
	for (s = value; s[0]; s++) {
		char c = s[0];

		len++;
		if (   (c >= '0' && c <= '9')
		    || (c >= 'a' && c <= 'z')
		    || (c >= 'A' && c <= 'Z')
		    || NM_IN_SET (c, '_', '-', ':', '/'))
			continue;
		needs_quotation = TRUE;
		if (c == '\'')
			has_single_quote = TRUE;
	}
	if (!needs_quotation)
		return value;

	if (!has_single_quote) {
		result = g_malloc (len + 2 + 1);
		result[0] = '\'';
		memcpy (&result[1], value, len);
		result[1 + len] = '\'';
		result[2 + len] = '\0';
	} else {
		i_result = result = g_malloc (len * 2 + 3);
		*(i_result++) = '"';
		for (s = value; s[0]; s++) {
			if (NM_IN_SET (s[0], '\\', '"'))
				*(i_result++) = '\\';
			*(i_result++) = s[0];
		}
		*(i_result++) = '"';
		*(i_result++) = '\0';
	}

	*buf = result;
	return result;
}

static void
args_write_line_v (GString *f, gsize nargs, const char **args)
{
	gsize i;
	gboolean printed;

	nm_assert (args);
	nm_assert (args[0]);

	for (i = 0; i < nargs; i++) {
		gs_free char *tmp = NULL;

		/* NULL is skipped. This is for convenience to specify
		 * optional arguments. */
		if (!args[i])
			continue;

		if (printed)
			g_string_append_c (f, ' ');
		printed = TRUE;
		g_string_append (f, escape_arg (args[i], &tmp));
	}
	g_string_append_c (f, '\n');
}
#define args_write_line(f, ...) args_write_line_v(f, NM_NARG (__VA_ARGS__), (const char *[]) { __VA_ARGS__ })

static void
args_write_line_int64 (GString *f, const char *key, gint64 value)
{
	char tmp[64];

	args_write_line (f, key, nm_sprintf_buf (tmp, "%"G_GINT64_FORMAT, value));
}

static void
args_write_line_int64_str (GString *f, const char *key, const char *value)
{
	gint64 v;

	v = _nm_utils_ascii_str_to_int64 (value, 10, G_MININT64, G_MAXINT64, 0);
	if (errno)
		return;
	args_write_line_int64 (f, key, v);
}

static void
args_write_line_setting_value (GString *f,
                               const char *tag_key,
                               NMSettingVpn *s_vpn,
                               const char *setting_key)
{
	const char *value;

	nm_assert (tag_key && tag_key[0]);
	nm_assert (NM_IS_SETTING_VPN (s_vpn));
	nm_assert (setting_key && setting_key[0]);

	value = nm_setting_vpn_get_data_item (s_vpn, setting_key);
	if (_arg_is_set (value))
		args_write_line (f, tag_key, value);
}

/*****************************************************************************/

static GString *
do_export_create (NMConnection *connection, const char *path, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4;
	NMSettingVpn *s_vpn;
	const char *value;
	const char *gateways = NULL;
	char **gw_list, **gw_iter;
	gs_free char *cacert = NULL;
	const char *connection_type = NULL;
	gs_free char *user_cert = NULL;
	gs_free char *private_key = NULL;
	gs_free char *static_key = NULL;
	const char *static_key_direction = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	gs_free char *tls_auth = NULL;
	const char *tls_auth_dir = NULL;
	gs_free char *device = NULL;
	const char *device_type = NULL;
	const char *device_default = "tun";
	gboolean proto_udp = TRUE;
	gboolean use_lzo = FALSE;
	gboolean use_float = FALSE;
	gboolean reneg_exists = FALSE;
	glong reneg = 0;
	gboolean keysize_exists = FALSE;
	guint32 keysize = 0;
	gboolean randomize_hosts = FALSE;
	gboolean tun_ipv6 = FALSE;
	const char *proxy_type = NULL;
	const char *proxy_server = NULL;
	const char *proxy_port = NULL;
	const char *proxy_retry = NULL;
	const char *proxy_username = NULL;
	const char *proxy_password = NULL;
	int i;
	guint num;
	nm_auto(_auto_free_gstring_p) GString *f = NULL;
	gs_free_error GError *local = NULL;

	if (!path || !path[0]) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("missing path argument"));
		return NULL;
	}

	s_con = nm_connection_get_setting_connection (connection);
	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_con || !s_vpn) {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("connection is not a valid OpenVPN connection"));
		return NULL;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
	if (_arg_is_set (value))
		gateways = value;
	else {
		g_set_error_literal (error,
		                     OPENVPN_EDITOR_PLUGIN_ERROR,
		                     OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		                     _("connection was incomplete (missing gateway)"));
		return NULL;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (_arg_is_set (value))
		connection_type = value;

	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (_arg_is_set (value))
			cacert = nmv_utils_str_utf8safe_unescape (value);
	}

	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
		if (_arg_is_set (value))
			user_cert = nmv_utils_str_utf8safe_unescape (value);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (_arg_is_set (value))
			private_key = nmv_utils_str_utf8safe_unescape (value);
	}

	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (_arg_is_set (value))
			static_key = nmv_utils_str_utf8safe_unescape (value);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
		if (_arg_is_set (value))
			static_key_direction = value;
	}

	/* Advanced values start */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (_arg_is_set (value)) {
		reneg_exists = TRUE;
		reneg = strtol (value, NULL, 10);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP);
	if (value && !strcmp (value, "yes"))
		proto_udp = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV);
	if (_arg_is_set (value))
		device = nmv_utils_str_utf8safe_unescape (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE);
	if (_arg_is_set (value))
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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE);
	if (_arg_is_set (value)) {
		keysize_exists = TRUE;
		keysize = strtol (value, NULL, 10);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
	if (_arg_is_set (value))
		local_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
	if (_arg_is_set (value))
		remote_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA);
	if (_arg_is_set (value))
		tls_auth = nmv_utils_str_utf8safe_unescape (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR);
	if (_arg_is_set (value))
		tls_auth_dir = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM);
	if (value && !strcmp (value, "yes"))
		randomize_hosts = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUN_IPV6);
	if (value && !strcmp (value, "yes"))
		tun_ipv6 = TRUE;

	/* Advanced values end */

	f = g_string_sized_new (512);

	args_write_line (f, "client");

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

		args_write_line (f,
		                 "remote",
		                 *gw_iter,
		                 tmp_port
		                     ?: (tmp_proto
		                             ? (nm_streq (tmp_proto, "udp") ? "1194" : "443")
		                             : NULL),
		                 tmp_proto);
	}
	g_strfreev (gw_list);

	if (randomize_hosts)
		args_write_line (f, "remote-random");

	if (tun_ipv6)
		args_write_line (f, "tun-ipv6");

	/* Handle PKCS#12 (all certs are the same file) */
	if (   cacert && user_cert && private_key
	    && !strcmp (cacert, user_cert) && !strcmp (cacert, private_key))
		args_write_line (f, "pkcs12", cacert);
	else {
		if (cacert)
			args_write_line (f, "ca", cacert);
		if (user_cert)
			args_write_line (f, "cert", user_cert);
		if (private_key)
			args_write_line (f, "key", private_key);
	}

	if (   !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		args_write_line (f, "auth-user-pass");

	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		if (static_key)
			args_write_line (f, "secret", static_key, static_key_direction);
	}

	if (reneg_exists)
		args_write_line_int64 (f, "reneg-sec", reneg);

	args_write_line_setting_value (f, "cipher", s_vpn, NM_OPENVPN_KEY_CIPHER);

	if (keysize_exists)
		args_write_line_int64 (f, "keysize", keysize);

	if (use_lzo)
		args_write_line (f, "comp-lzo", "yes");

	if (use_float)
		args_write_line (f, "float");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX);
	if (nm_streq0 (value, "yes"))
		args_write_line (f, TAG_MSSFIX);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU);
	if (_arg_is_set (value))
		args_write_line_int64_str (f, TAG_TUN_MTU, value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	if (_arg_is_set (value))
		args_write_line_int64_str (f, TAG_FRAGMENT, value);

	args_write_line (f,
	                 "dev",
	                 device ?: (device_type ?: device_default));
	if (device_type)
		args_write_line (f, "dev-type", device_type);
	args_write_line (f, "proto", proto_udp ? "udp" : "tcp");

	args_write_line_setting_value (f, "port", s_vpn, NM_OPENVPN_KEY_PORT);

	args_write_line_setting_value (f, "ping", s_vpn, NM_OPENVPN_KEY_PING);

	args_write_line_setting_value (f, "ping-exit", s_vpn, NM_OPENVPN_KEY_PING_EXIT);

	args_write_line_setting_value (f, "ping-restart", s_vpn, NM_OPENVPN_KEY_PING_RESTART);

	if (local_ip && remote_ip)
		args_write_line (f, "ifconfig", local_ip, remote_ip);

	if (   !strcmp(connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp(connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {

		args_write_line_setting_value (f, "tls-remote", s_vpn, NM_OPENVPN_KEY_TLS_REMOTE);
		args_write_line_setting_value (f, "remote-cert-tls", s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS);

		if (tls_auth) {
			args_write_line (f,
			                 "tls-auth",
			                 tls_auth,
			                 tls_auth_dir);
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

			args_write_line (f,
			                 "http-proxy",
			                 proxy_server,
			                 proxy_port,
			                 proxy_username ? authfile : NULL);
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				args_write_line (f, "http-proxy-retry");

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
			args_write_line (f, "socks-proxy", proxy_server, proxy_port);
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				args_write_line (f, "socks-proxy-retry");
		}
	}

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4) {
#ifdef NM_OPENVPN_OLD
		num = nm_setting_ip4_config_get_num_routes (s_ip4);
#else
		num = nm_setting_ip_config_get_num_routes (s_ip4);
#endif
		for (i = 0; i < num; i++) {
			char netmask_str[INET_ADDRSTRLEN] = { 0 };
			const char *next_hop_str, *dest_str;
			in_addr_t netmask;
			guint prefix;
			guint64 metric;
			char metric_buf[50];

#ifdef NM_OPENVPN_OLD
			char next_hop_str_buf[INET_ADDRSTRLEN] = { 0 };
			char dest_str_buf[INET_ADDRSTRLEN] = { 0 };
			in_addr_t dest, next_hop;
			NMIP4Route *route = nm_setting_ip4_config_get_route (s_ip4, i);

			dest = nm_ip4_route_get_dest (route);
			inet_ntop (AF_INET, (const void *) &dest, dest_str_buf, sizeof (dest_str_buf));
			dest_str = dest_str_buf;

			next_hop = nm_ip4_route_get_next_hop (route);
			inet_ntop (AF_INET, (const void *) &next_hop, next_hop_str_buf, sizeof (next_hop_str_buf));
			next_hop_str = next_hop_str_buf;

			prefix = nm_ip4_route_get_prefix (route);
			metric = nm_ip4_route_get_metric (route);
#else
			NMIPRoute *route = nm_setting_ip_config_get_route (s_ip4, i);

			dest_str = nm_ip_route_get_dest (route);
			next_hop_str = nm_ip_route_get_next_hop (route) ? : "0.0.0.0",
			prefix = nm_ip_route_get_prefix (route);
			metric = nm_ip_route_get_metric (route);
#endif
			netmask = nm_utils_ip4_prefix_to_netmask (prefix);
			inet_ntop (AF_INET, (const void *) &netmask, netmask_str, sizeof (netmask_str));

			args_write_line (f,
			                 "route",
			                 dest_str,
			                 netmask_str,
			                 next_hop_str,
			                 metric == -1 ? NULL : nm_sprintf_buf (metric_buf, "%u", (unsigned) metric));
		}
	}

	/* Add hard-coded stuff */
	args_write_line (f, "nobind");
	args_write_line (f, "auth-nocache");
	args_write_line (f, "script-security", "2");
	args_write_line (f, "persist-key");
	args_write_line (f, "persist-tun");
	args_write_line (f, "user", "openvpn");
	args_write_line (f, "group", "openvpn");

	return nm_unauto (&f);
}

gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	nm_auto(_auto_free_gstring_p) GString *f = NULL;
	gs_free_error GError *local = NULL;

	f = do_export_create (connection, path, error);
	if (!f)
		return FALSE;

	if (!g_file_set_contents (path, f->str, f->len, &local)) {
		g_set_error (error,
		             OPENVPN_EDITOR_PLUGIN_ERROR,
		             OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN,
		             _("failed to write file: %s"),
		             local->message);
		return FALSE;
	}

	return TRUE;
}

