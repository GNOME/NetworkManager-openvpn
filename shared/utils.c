/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <errno.h>

#include "nm-default.h"
#include "utils.h"
#include "nm-macros-internal.h"

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

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
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

/*****************************************************************************/

/* _nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
_nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
	gint64 v;
	size_t len;
	char buf[64], *s, *str_free = NULL;

	if (str) {
		while (g_ascii_isspace (str[0]))
			str++;
	}
	if (!str || !str[0]) {
		errno = EINVAL;
		return fallback;
	}

	len = strlen (str);
	if (g_ascii_isspace (str[--len])) {
		/* backward search the first non-ws character.
		 * We already know that str[0] is non-ws. */
		while (g_ascii_isspace (str[--len]))
			;

		/* str[len] is now the last non-ws character... */
		len++;

		if (len >= sizeof (buf))
			s = str_free = g_malloc (len + 1);
		else
			s = buf;

		memcpy (s, str, len);
		s[len] = 0;

		nm_assert (len > 0 && len < strlen (str) && len == strlen (s));
		nm_assert (!g_ascii_isspace (str[len-1]) && g_ascii_isspace (str[len]));
		nm_assert (strncmp (str, s, len) == 0);

		str = s;
	}

	errno = 0;
	v = g_ascii_strtoll (str, &s, base);

	if (errno != 0)
		v = fallback;
	else if (s[0] != 0) {
		errno = EINVAL;
		v = fallback;
	} else if (v > max || v < min) {
		errno = ERANGE;
		v = fallback;
	}

	if (G_UNLIKELY (str_free))
		g_free (str_free);
	return v;
}

/*****************************************************************************/

/**
 * nmv_utils_str_utf8safe_escape:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 *
 * Does something similar like g_strescape(), where the operation
 * can be reverted by g_strcompress(). However, the UTF-8 characters
 * are not escaped at all (except the escape character '\\'). It only
 * escapes non-UTF-8 characters. This way it is possible to transfer
 * the string as UTF-8 via D-Bus.
 * Also, it can be directly displayed to the user and will show as
 * UTF-8, with exception of the escape character and characters in
 * different encodings.
 *
 * Returns: the escaped input string in UTF-8 encoding. The returned
 *   value should be freed with g_free().
 *   The escaping can be reverted by g_strcompress().
 **/
char *
nmv_utils_str_utf8safe_escape (const char *str)
{
	char *s = NULL;

	nmv_utils_str_utf8safe_escape_c (str, &s);
	return s ? : g_strdup (str);
}

/**
 * nmv_utils_str_utf8safe_escape_c:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @str_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Like nmv_utils_str_utf8safe_escape(), except that the string
 * is only copied if it is actually necessary. In that case,
 * @str_free will contain the allocated string which must be
 * freed with g_free().
 * Otherwise, @str_free is %NULL and the input string is returned.
 *
 * Returns: the escaped input string. If no escaping is necessary,
 *   it returns @str. Otherwise, an allocated string @str_free is
 *   returned.
 *   The escaping can be reverted by g_strcompress().
 **/
const char *
nmv_utils_str_utf8safe_escape_c (const char *str, char **str_free)
{
	const char *p = NULL;
	guchar ch;
	GString *s;

	g_return_val_if_fail (str_free, NULL);

	*str_free = NULL;
	if (!str || !str[0])
		return str;

	if (g_utf8_validate (str, -1, &p)) {
		if (!strchr (str, '\\'))
			return str;
	}

	s = g_string_sized_new (30);

	do {
		for (; str < p; str++) {
			if (str[0] == '\\')
				g_string_append (s, "\\\\");
			else
				g_string_append_c (s, str[0]);
		}

		ch = p[0];
		if (ch == '\0')
			break;
		g_string_append_c (s, '\\');
		g_string_append_c (s, '0' + ((ch >> 6) & 07));
		g_string_append_c (s, '0' + ((ch >> 3) & 07));
		g_string_append_c (s, '0' + ( ch       & 07));

		str = &p[1];
		g_utf8_validate (str, -1, &p);
	} while (TRUE);

	*str_free = g_string_free (s, FALSE);
	return *str_free;
}

char *
nmv_utils_str_utf8safe_unescape (const char *str)
{
	if (!str)
		return NULL;
	return g_strcompress (str);
}

const char *
nmv_utils_str_utf8safe_unescape_c (const char *str, char **str_free)
{
	g_return_val_if_fail (str_free, NULL);

	if (!str || !strchr (str, '\\')) {
		*str_free = NULL;
		return str;
	}
	*str_free = g_strcompress (str);
	return *str_free;
}

/*****************************************************************************/

