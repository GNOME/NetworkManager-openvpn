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

#ifndef UTILS_H
#define UTILS_H

#include <glib.h>

gboolean is_pkcs12 (const char *filepath);

gboolean is_encrypted (const char *filename);

gint64 _nm_utils_ascii_str_to_int64 (const char *str, guint base, gint64 min, gint64 max, gint64 fallback);

char *      nmv_utils_str_utf8safe_escape     (const char *str);
const char *nmv_utils_str_utf8safe_escape_c   (const char *str, char **out_clone);
char *      nmv_utils_str_utf8safe_unescape   (const char *str);
const char *nmv_utils_str_utf8safe_unescape_c (const char *str, char **str_free);

#endif  /* UTILS_H */

