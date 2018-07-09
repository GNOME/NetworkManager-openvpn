/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_H__
#define __NM_DEFAULT_H__

/* makefiles define NETWORKMANAGER_COMPILATION for compiling NetworkManager.
 * Depending on which parts are compiled, different values are set. */
#define NM_NETWORKMANAGER_COMPILATION_DEFAULT             0x0001
#define NM_NETWORKMANAGER_COMPILATION_LIB_BASE            0x0002
#define NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR          0x0004
#define NM_NETWORKMANAGER_COMPILATION_LIB                 (0x0002 | 0x0004)

/* special flag, to indicate that we build a legacy library. That is, we link against
 * deprecated libnm-util/libnm-glib instead against libnm. */
#define NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL     0x0010

/*****************************************************************************/

#include <config.h>

/* always include these headers for our internal source files. */

#include "nm-utils/nm-macros-internal.h"

#include "nm-version.h"
#include "nm-service-defines.h"

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB)

#include <glib/gi18n-lib.h>

#else

#include <glib/gi18n.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB */

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL)

#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-8021x.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vpn.h>
#include <nm-utils.h>
#include <nm-vpn-plugin-ui-interface.h>

#define nm_simple_connection_new nm_connection_new
#define NM_SETTING_IP_CONFIG NM_SETTING_IP4_CONFIG
#define NM_SETTING_IP_CONFIG_METHOD NM_SETTING_IP4_CONFIG_METHOD
#define NM_SETTING_IP_CONFIG_NEVER_DEFAULT NM_SETTING_IP4_CONFIG_NEVER_DEFAULT
#define NMSettingIPConfig NMSettingIP4Config

#define NMV_EDITOR_PLUGIN_ERROR                     NM_SETTING_VPN_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED              NM_SETTING_VPN_ERROR_UNKNOWN
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_SETTING_VPN_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY    NM_SETTING_VPN_ERROR_MISSING_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN        NM_SETTING_VPN_ERROR_UNKNOWN
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_SETTING_VPN_ERROR_UNKNOWN
#define NMV_EDITOR_PLUGIN_ERROR_FILE_INVALID        NM_SETTING_VPN_ERROR_UNKNOWN

#define _nm_utils_is_valid_iface_name(n)            nm_utils_iface_valid_name(n)

#else /* NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL */

#include <NetworkManager.h>

#define NMV_EDITOR_PLUGIN_ERROR                     NM_CONNECTION_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED              NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_CONNECTION_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY    NM_CONNECTION_ERROR_MISSING_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN        NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_INVALID        NM_CONNECTION_ERROR_FAILED

#define _nm_utils_is_valid_iface_name(n)            nm_utils_is_valid_iface_name(n, NULL)

#endif /* NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL */

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR

#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_UTIL)
#include <nm-ui-utils.h>
#include <nm-cert-chooser.h>
#else
#include <nma-ui-utils.h>
#include <nma-cert-chooser.h>
#endif

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR */

/*****************************************************************************/

#endif /* __NM_DEFAULT_H__ */
