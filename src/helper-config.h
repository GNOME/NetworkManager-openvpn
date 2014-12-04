/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service - openvpn integration with NetworkManager
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

#ifndef HELPER_CONFIG_H
#define HELPER_CONFIG_H

#include <glib.h>
#include <dbus/dbus-glib.h>

#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))
#define DBUS_TYPE_G_PTR_ARRAY_OF_STRING    (dbus_g_type_get_collection ("GPtrArray", G_TYPE_STRING))
#define DBUS_TYPE_G_IP6_ROUTE              (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE     (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_IP6_ROUTE))

gboolean helper_generate_config (const char **args,
                                 gboolean is_tapdev,
                                 gboolean is_restart,
                                 GHashTable **out_config,
                                 GHashTable **out_ip4_config,
                                 GHashTable **out_ip6_config,
                                 GError **error);

#endif /* HELPER_CONFIG_H */
