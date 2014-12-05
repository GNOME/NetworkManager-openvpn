/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service-openvpn-helper - helper called after OpenVPN established
 * a connection, uses DBUS to send information back to nm-openvpn-service
 *
 * Tim Niemueller [www.niemueller.de]
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 * (C) Copyright 2005 Tim Niemueller
 *
 * $Id: nm-openvpn-service-openvpn-helper.c 4170 2008-10-11 14:44:45Z dcbw $
 * 
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-openvpn-service.h"
#include "helper-config.h"

#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

extern char **environ;

static gboolean helper_debug = FALSE;

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *error = NULL;

	g_warning ("nm-openvpn-service-openvpn-helper failed: %s", reason);

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   NM_DBUS_SERVICE_OPENVPN,
	                                   NM_VPN_DBUS_PLUGIN_PATH,
	                                   NM_VPN_DBUS_PLUGIN_INTERFACE);

	if (!dbus_g_proxy_call (proxy, "SetFailure", &error,
	                        G_TYPE_STRING, reason, G_TYPE_INVALID,
	                        G_TYPE_INVALID))
		g_warning ("Could not send failure information: %s", error->message);

	g_object_unref (proxy);
	g_clear_error (&error);

	exit (1);
}

static void
send_config (DBusGConnection *connection, GHashTable *config,
             GHashTable *ip4config, GHashTable *ip6config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   NM_DBUS_SERVICE_OPENVPN,
	                                   NM_VPN_DBUS_PLUGIN_PATH,
	                                   NM_VPN_DBUS_PLUGIN_INTERFACE);

	if (!dbus_g_proxy_call (proxy, "SetConfig", &err,
	                        DBUS_TYPE_G_MAP_OF_VARIANT,
	                        config,
	                        G_TYPE_INVALID,
	                        G_TYPE_INVALID) && err) {
		g_warning ("Could not send configuration information: %s", err->message);
		g_clear_error (&err);
	}

	if (ip4config) {
		if (!dbus_g_proxy_call (proxy, "SetIp4Config", &err,
		                        DBUS_TYPE_G_MAP_OF_VARIANT,
		                        ip4config,
		                        G_TYPE_INVALID,
		                        G_TYPE_INVALID) && err) {
			g_warning ("Could not send IPv4 configuration information: %s", err->message);
			g_clear_error (&err);
		}
	}

	if (ip6config) {
		if (!dbus_g_proxy_call (proxy, "SetIp6Config", &err,
		                        DBUS_TYPE_G_MAP_OF_VARIANT,
		                        ip6config,
		                        G_TYPE_INVALID,
		                        G_TYPE_INVALID) && err) {
			g_warning ("Could not send IPv6 configuration information: %s", err->message);
			g_clear_error (&err);
		}
	}

	g_object_unref (proxy);
}

int
main (int argc, char *argv[])
{
	DBusGConnection *connection;
	GHashTable *config = NULL, *ip4_config = NULL, *ip6_config = NULL;
	char *tmp, **iter;
	int i;
	GError *error = NULL;
	int tapdev = -1;
	int shift = 0;
	gboolean is_restart;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv[i], "--")) {
			i++;
			break;
		}
		if (!strcmp (argv[i], "--helper-debug"))
			helper_debug = TRUE;
		else if (!strcmp (argv[i], "--tun"))
			tapdev = 0;
		else if (!strcmp (argv[i], "--tap"))
			tapdev = 1;
		else
			break;
	}
	shift = i - 1;

	if (helper_debug) {
		GString *args;

		args = g_string_new (NULL);
		for (i = 0; i < argc; i++) {
			if (i > 0)
				g_string_append_c (args, ' ');
			if (shift && 1 + shift == i)
				g_string_append (args, "  ");
			tmp = g_strescape (argv[i], NULL);
			g_string_append_printf (args, "\"%s\"", tmp);
			g_free (tmp);
		}

		g_message ("command line: %s", args->str);
		g_string_free (args, TRUE);
		g_message ("openvpn script environment ---------------------------");
		iter = environ;
		while (iter && *iter)
			g_message ("%s", *iter++);
		g_message ("------------------------------------------------------");
	}

	/* shift the arguments to the right leaving only those provided by openvpn */
	argv[shift] = argv[0];
	argv += shift;
	argc -= shift;

	is_restart = argc >= 7 && !g_strcmp0 (argv[6], "restart");

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!connection) {
		g_warning ("Could not get the system bus: %s", error->message);
		exit (1);
	}

	if (helper_generate_config ((const char **) argv, FALSE, is_restart, &config, &ip4_config, &ip6_config, &error))
		send_config (connection, config, ip4_config, ip6_config);
	else
		helper_failed (connection, error ? error->message : "(unknown)");

	g_clear_pointer (&config, g_hash_table_destroy);
	g_clear_pointer (&ip4_config, g_hash_table_destroy);
	g_clear_pointer (&ip6_config, g_hash_table_destroy);

	return 0;
}
