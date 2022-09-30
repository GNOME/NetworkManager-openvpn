/*
 * network-manager-openvpn - OpenVPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright (C) 2010 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "nm-utils/nm-shared-utils.h"

gboolean
is_pkcs12 (const char *filepath)
{
	NMSetting8021xCKFormat ck_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021x *s_8021x;

	if (!filepath || !strlen (filepath))
		return FALSE;

	if (!g_file_test (filepath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
		return FALSE;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_return_val_if_fail (s_8021x != NULL, FALSE);

	nm_setting_802_1x_set_private_key (s_8021x,
	                                   filepath,
	                                   NULL,
	                                   NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                   &ck_format,
	                                   NULL);
	g_object_unref (s_8021x);

	return (ck_format == NM_SETTING_802_1X_CK_FORMAT_PKCS12);
}

#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"
#define PKCS8_TAG "-----BEGIN ENCRYPTED PRIVATE KEY-----"

/** Checks if a file appears to be an encrypted private key.
 * @param filename the path to the file
 * @return returns true if the key is encrypted, false otherwise
 */
gboolean
is_encrypted (const char *filename)
{
	GIOChannel *pem_chan;
	char *str = NULL;
	gboolean encrypted = FALSE;

	if (!filename || !strlen (filename))
		return FALSE;

	if (is_pkcs12 (filename))
		return TRUE;

	pem_chan = g_io_channel_new_file (filename, "r", NULL);
	if (!pem_chan)
		return FALSE;

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
		if (str) {
			if (g_str_has_prefix (str, PROC_TYPE_TAG) || g_str_has_prefix (str, PKCS8_TAG)) {
				encrypted = TRUE;
				break;
			}
			g_free (str);
		}
	}

	g_io_channel_shutdown (pem_chan, FALSE, NULL);
	g_io_channel_unref (pem_chan);
	return encrypted;
}

static gboolean
_is_inet6_addr (const char *str, gboolean with_square_brackets)
{
	struct in6_addr a;
	gsize l;

	if (   with_square_brackets
	    && str[0] == '[') {
		l = strlen (str);
		if (str[l - 1] == ']') {
			gs_free char *s = g_strndup (&str[1], l - 2);

			return inet_pton (AF_INET6, s, &a) == 1;
		}
	}
	return inet_pton (AF_INET6, str, &a) == 1;
}

NMOvpnAllowCompression
nmovpn_allow_compression_from_options (const char *allow_compression)
{
    if (nm_streq0 (allow_compression, "asym"))
		return NMOVPN_ALLOW_COMPRESSION_ASYM;
	if (nm_streq0 (allow_compression, "yes"))
		return NMOVPN_ALLOW_COMPRESSION_YES;
	if (nm_streq0 (allow_compression, "no"))
		return NMOVPN_ALLOW_COMPRESSION_NO;

	return NMOVPN_ALLOW_COMPRESSION_ASYM;
}

void
nmovpn_allow_compression_to_options (NMOvpnAllowCompression allow_compression,
                                     const char **opt_allow_compression)
{
    NM_SET_OUT (opt_allow_compression, NULL);

    switch (allow_compression) {
    case NMOVPN_ALLOW_COMPRESSION_ASYM:
        NM_SET_OUT (opt_allow_compression, "asym");
        break;
    case NMOVPN_ALLOW_COMPRESSION_YES:
        NM_SET_OUT (opt_allow_compression, "yes");
        break;
    case NMOVPN_ALLOW_COMPRESSION_NO:
        NM_SET_OUT (opt_allow_compression, "no");
        break;
    }
}

NMOvpnComp
nmovpn_compression_from_options (const char *comp_lzo, const char *compress)
{
	if (nm_streq0 (compress, "lzo"))
		return NMOVPN_COMP_LZO;
	if (nm_streq0 (compress, "lz4"))
		return NMOVPN_COMP_LZ4;
	if (nm_streq0 (compress, "lz4-v2"))
		return NMOVPN_COMP_LZ4_V2;
	if (nm_streq0 (compress, "yes"))
		return NMOVPN_COMP_AUTO;

	if (nm_streq0 (comp_lzo, "yes"))
		return NMOVPN_COMP_LZO;
	if (nm_streq0 (comp_lzo, "no-by-default"))
		return NMOVPN_COMP_LEGACY_LZO_DISABLED;
	if (nm_streq0 (comp_lzo, "adaptive"))
		return NMOVPN_COMP_LEGACY_LZO_ADAPTIVE;

	return NMOVPN_COMP_DISABLED;
}

void
nmovpn_compression_to_options (NMOvpnComp comp,
                               const char **comp_lzo,
                               const char **compress)
{
	NM_SET_OUT (comp_lzo, NULL);
	NM_SET_OUT (compress, NULL);

	switch (comp) {
	case NMOVPN_COMP_DISABLED:
		break;
	case NMOVPN_COMP_LZO:
		NM_SET_OUT (compress, "lzo");
		break;
	case NMOVPN_COMP_LZ4:
		NM_SET_OUT (compress, "lz4");
		break;
	case NMOVPN_COMP_LZ4_V2:
		NM_SET_OUT (compress, "lz4-v2");
		break;
	case NMOVPN_COMP_AUTO:
		NM_SET_OUT (compress, "yes");
		break;
	case NMOVPN_COMP_LEGACY_LZO_DISABLED:
		NM_SET_OUT (comp_lzo, "no-by-default");
		break;
	case NMOVPN_COMP_LEGACY_LZO_ADAPTIVE:
		NM_SET_OUT (comp_lzo, "adaptive");
		break;
	}
}

/**
 * nmovpn_remote_parse:
 * @str: the input string to be split. It is modified inplace.
 * @out_buf: an allocated string, to which the other arguments
 *   point to. Must be freed by caller.
 * @out_host: pointer to the host out argument.
 * @out_port: pointer to the port out argument.
 * @out_proto: pointer to the proto out argument.
 * @error:
 *
 * Splits @str in three parts host, port and proto.
 *
 * Returns: -1 on success or index in @str of first invalid character.
 *  Note that the error index can be at strlen(str), if some data is missing.
 **/
gssize
nmovpn_remote_parse (const char *str,
                     char **out_buf,
                     const char **out_host,
                     const char **out_port,
                     const char **out_proto,
                     GError **error)
{
	gs_free char *str_copy = NULL;
	char *t;
	char *host = NULL;
	char *port = NULL;
	char *proto = NULL;
	gssize idx_fail;

	g_return_val_if_fail (str, 0);
	if (!out_buf) {
		/* one can omit @out_buf only if also no other out-arguments
		 * are requested. */
		if (out_host || out_port || out_proto)
			g_return_val_if_reached (0);
	}
	g_return_val_if_fail (!error || !*error, 0);

	t = strchr (str, ' ');
	if (!t)
		t = strchr (str, ',');
	if (t) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("invalid delimiter character '%c'"), t[0]);
		idx_fail = t - str;
		goto out_fail;
	}

	if (!g_utf8_validate (str, -1, (const char **) &t)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("invalid non-utf-8 character"));
		idx_fail = t - str;
		goto out_fail;
	}

	str_copy = g_strdup (str);

	/* we already checked that there is no space above.
	 * Strip tabs nonetheless. */
	host = nm_str_skip_leading_spaces (str_copy);
	g_strchomp (host);

	t = strrchr (host, ':');
	if (   t
	    && !_is_inet6_addr (host, TRUE)) {
		t[0] = '\0';
		port = &t[1];
		t = strrchr (host, ':');
		if (   t
		    && !_is_inet6_addr (host, TRUE)) {
			t[0] = '\0';
			proto = port;
			port = &t[1];
		}
	}

	if (!host[0]) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             _("empty host"));
		idx_fail = host - str_copy;
		goto out_fail;
	}
	if (port) {
		if (!port[0]) {
			/* allow empty port like "host::udp". */
			port = NULL;
		} else if (_nm_utils_ascii_str_to_int64 (port, 10, 1, 0xFFFF, 0) == 0) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             _("invalid port"));
			idx_fail = port - str_copy;
			goto out_fail;
		}
	}
	if (proto) {
		if (!proto[0]) {
			/* allow empty proto, so that host can contain ':'. */
			proto = NULL;
		} else if (!NM_IN_STRSET (proto, NMOVPN_PROTCOL_TYPES)) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             _("invalid protocol"));
			idx_fail = proto - str_copy;
			goto out_fail;
		}
	}

	if (out_buf) {
		*out_buf = g_steal_pointer (&str_copy);
		if (   host[0] == '['
		    && _is_inet6_addr (host, TRUE)
		    && !_is_inet6_addr (host, FALSE)) {
			gsize l;

			host++;
			l = strlen (host);
			nm_assert (l > 0 && host[l - 1] == ']');
			host[l - 1] = '\0';
			nm_assert (_is_inet6_addr (host, FALSE));
		}
		NM_SET_OUT (out_host, host);
		NM_SET_OUT (out_port, port);
		NM_SET_OUT (out_proto, proto);
	}
	return -1;

out_fail:
	if (out_buf) {
		*out_buf = NULL;
		NM_SET_OUT (out_host, NULL);
		NM_SET_OUT (out_port, NULL);
		NM_SET_OUT (out_proto, NULL);
	}
	return idx_fail;
}

/*****************************************************************************/

guint
nmovpn_version_parse (const char *version_str)
{
	const char *s;
	guint v_x;
	guint v_y;
	guint v_z;

	/* the output for --version starts with title_string, which starts with PACKAGE_STRING,
	 * which looks like "OpenVPN 2.#...". Do a strict parsing here... */
	if (   !version_str
	    || !g_str_has_prefix (version_str, "OpenVPN 2."))
		return NMOVPN_VERSION_UNKNOWN;
	s = &version_str[NM_STRLEN ("OpenVPN 2.")];

	if (!g_ascii_isdigit (s[0]))
		return NMOVPN_VERSION_UNKNOWN;

	v_x = 2;

	v_y = 0;
	do {
		if (v_y > G_MAXINT / 100)
			return NMOVPN_VERSION_UNKNOWN;
		v_y = (v_y * 10) + (s[0] - '0');
	} while (g_ascii_isdigit ((++s)[0]));
	if (v_y > 99)
		return NMOVPN_VERSION_UNKNOWN;

	v_z = 0;
	if (s[0] == '.') {
		s++;
		do {
			if (v_z > G_MAXINT / 100)
				break;
			v_z = (v_z * 10) + (s[0] - '0');
		} while (g_ascii_isdigit ((++s)[0]));
	}
	if (v_z > 99)
		v_z = 0;

	return nmovpn_version_encode (v_x, v_y, v_z);
}
