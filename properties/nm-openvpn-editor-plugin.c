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
 * Based on work by David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-openvpn-editor-plugin.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "nm-utils/nm-vpn-plugin-utils.h"

#include "import-export.h"

#define OPENVPN_PLUGIN_NAME    _("OpenVPN")
#define OPENVPN_PLUGIN_DESC    _("Compatible with the OpenVPN server.")

/*****************************************************************************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void openvpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenvpnEditorPlugin, openvpn_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               openvpn_editor_plugin_interface_init))

/*****************************************************************************/

static NMConnection *
import (NMVpnEditorPlugin *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	char *contents = NULL;
	gsize contents_len;

	if (!g_file_get_contents (path, &contents, &contents_len, error))
		return NULL;

	connection = do_import (path, contents, contents_len, error);

	g_free (contents);
	return connection;
}

static gboolean
export (NMVpnEditorPlugin *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	return do_export (path, connection, error);
}

static char *
get_suggested_filename (NMVpnEditorPlugin *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s (openvpn).conf", id);
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	gpointer gtk3_only_symbol;
	GModule *self_module;
	const char *editor;

	g_return_val_if_fail (OPENVPN_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	self_module = g_module_open (NULL, 0);
	g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
	g_module_close (self_module);

	if (gtk3_only_symbol) {
		editor = "libnm-vpn-plugin-openvpn-editor.so";
	} else {
		editor = "libnm-gtk4-vpn-plugin-openvpn-editor.so";
	}

	return nm_vpn_plugin_utils_load_editor (editor,
						"nm_vpn_editor_factory_openvpn",
						_call_editor_factory,
						iface,
						connection,
						NULL,
						error);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, OPENVPN_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, OPENVPN_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_VPN_SERVICE_TYPE_OPENVPN);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openvpn_editor_plugin_init (OpenvpnEditorPlugin *plugin)
{
}

static void
openvpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_filename = get_suggested_filename;
}

static void
openvpn_editor_plugin_class_init (OpenvpnEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

/*****************************************************************************/

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (OPENVPN_TYPE_EDITOR_PLUGIN, NULL);
}

