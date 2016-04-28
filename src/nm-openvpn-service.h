/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service - openvpn integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2008 Dan Williams <dcbw@redhat.com>
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

#ifndef NM_OPENVPN_SERVICE_H
#define NM_OPENVPN_SERVICE_H

#define NM_TYPE_OPENVPN_PLUGIN            (nm_openvpn_plugin_get_type ())
#define NM_OPENVPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPlugin))
#define NM_OPENVPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))
#define NM_IS_OPENVPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENVPN_PLUGIN))
#define NM_IS_OPENVPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OPENVPN_PLUGIN))
#define NM_OPENVPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMOpenvpnPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMOpenvpnPluginClass;

GType nm_openvpn_plugin_get_type (void);

NMOpenvpnPlugin *nm_openvpn_plugin_new (const char *bus_name);

#endif /* NM_OPENVPN_SERVICE_H */
