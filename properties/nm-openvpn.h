/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openvpn.h : GNOME UI dialogs for configuring openvpn VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifndef _NM_OPENVPN_H_
#define _NM_OPENVPN_H_

#include <glib-object.h>

#define OPENVPN_TYPE_PLUGIN_UI                (openvpn_editor_plugin_get_type ())
#define OPENVPN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENVPN_TYPE_PLUGIN_UI, OpenvpnPluginUi))
#define OPENVPN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENVPN_TYPE_PLUGIN_UI, OpenvpnPluginUiClass))
#define OPENVPN_IS_PLUGIN_UI(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENVPN_TYPE_PLUGIN_UI))
#define OPENVPN_IS_PLUGIN_UI_CLASS(klass)     (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENVPN_TYPE_PLUGIN_UI))
#define OPENVPN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENVPN_TYPE_PLUGIN_UI, OpenvpnPluginUiClass))

typedef struct _OpenvpnPluginUi OpenvpnPluginUi;
typedef struct _OpenvpnPluginUiClass OpenvpnPluginUiClass;

struct _OpenvpnPluginUi {
	GObject parent;
};

struct _OpenvpnPluginUiClass {
	GObjectClass parent;
};

GType openvpn_editor_plugin_get_type (void);


#define OPENVPN_TYPE_PLUGIN_UI_WIDGET            (openvpn_editor_plugin_widget_get_type ())
#define OPENVPN_EDITOR(obj)                      (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENVPN_TYPE_PLUGIN_UI_WIDGET, OpenvpnPluginUiWidget))
#define OPENVPN_EDITOR_CLASS(klass)              (G_TYPE_CHECK_CLASS_CAST ((klass), OPENVPN_TYPE_PLUGIN_UI_WIDGET, OpenvpnPluginUiWidgetClass))
#define OPENVPN_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENVPN_TYPE_PLUGIN_UI_WIDGET))
#define OPENVPN_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENVPN_TYPE_PLUGIN_UI_WIDGET))
#define OPENVPN_EDITOR_GET_CLASS(obj)            (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENVPN_TYPE_PLUGIN_UI_WIDGET, OpenvpnPluginUiWidgetClass))

typedef struct _OpenvpnPluginUiWidget OpenvpnPluginUiWidget;
typedef struct _OpenvpnPluginUiWidgetClass OpenvpnPluginUiWidgetClass;

struct _OpenvpnPluginUiWidget {
	GObject parent;
};

struct _OpenvpnPluginUiWidgetClass {
	GObjectClass parent;
};

GType openvpn_editor_plugin_widget_get_type (void);

#endif	/* _NM_OPENVPN_H_ */

