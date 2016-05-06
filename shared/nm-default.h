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

#ifndef NETWORKMANAGER_COMPILATION
/* For convenience, we don't require our Makefile.am to define
 * -DNETWORKMANAGER_COMPILATION. As we now include this internal header,
 *  we know we do a NETWORKMANAGER_COMPILATION. */
#define NETWORKMANAGER_COMPILATION NM_NETWORKMANAGER_COMPILATION_DEFAULT
#endif

/*****************************************************************************/

#include <config.h>

/* always include these headers for our internal source files. */

#include "nm-glib.h"
#include "nm-version.h"
#include "gsystem-local-alloc.h"
#include "nm-macros-internal.h"
#include "nm-openvpn-service-defines.h"

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB)

#include <glib/gi18n-lib.h>

#else

#include <glib/gi18n.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB */

/*****************************************************************************/

#ifdef NM_OPENVPN_OLD

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
#define NMSettingIPConfig NMSettingIP4Config

#define OPENVPN_EDITOR_PLUGIN_ERROR                     NM_SETTING_VPN_ERROR
#define OPENVPN_EDITOR_PLUGIN_ERROR_FAILED              NM_SETTING_VPN_ERROR_UNKNOWN
#define OPENVPN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_SETTING_VPN_ERROR_INVALID_PROPERTY
#define OPENVPN_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY    NM_SETTING_VPN_ERROR_MISSING_PROPERTY
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN    NM_SETTING_VPN_ERROR_UNKNOWN
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_SETTING_VPN_ERROR_UNKNOWN
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_INVALID        NM_SETTING_VPN_ERROR_UNKNOWN

#else /* !NM_OPENVPN_OLD */

#include <NetworkManager.h>

#define OPENVPN_EDITOR_PLUGIN_ERROR                     NM_CONNECTION_ERROR
#define OPENVPN_EDITOR_PLUGIN_ERROR_FAILED              NM_CONNECTION_ERROR_FAILED
#define OPENVPN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY    NM_CONNECTION_ERROR_INVALID_PROPERTY
#define OPENVPN_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY    NM_CONNECTION_ERROR_MISSING_PROPERTY
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_OPENVPN    NM_CONNECTION_ERROR_FAILED
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE   NM_CONNECTION_ERROR_FAILED
#define OPENVPN_EDITOR_PLUGIN_ERROR_FILE_INVALID        NM_CONNECTION_ERROR_FAILED

#endif /* NM_OPENVPN_OLD */

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR

#ifdef NM_OPENVPN_OLD
#include <nm-ui-utils.h>
#else /* NM_OPENVPN_OLD */
#include <nma-ui-utils.h>
#endif /* NM_OPENVPN_OLD */

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR */

/*****************************************************************************/

/**
 * The boolean type _Bool is C99 while we mostly stick to C89. However, _Bool is too
 * convinient to miss and is effectively available in gcc and clang. So, just use it.
 *
 * Usually, one would include "stdbool.h" to get the "bool" define which aliases
 * _Bool. We provide this define here, because we want to make use of it anywhere.
 * (also, stdbool.h is again C99).
 *
 * Using _Bool has advantages over gboolean:
 *
 * - commonly _Bool is one byte large, instead of gboolean's 4 bytes (because gboolean
 *   is a typedef for gint). Especially when having boolean fields in a struct, we can
 *   thereby easily save some space.
 *
 * - _Bool type guarantees that two "true" expressions compare equal. E.g. the follwing
 *   will not work:
 *        gboolean v1 = 1;
 *        gboolean v2 = 2;
 *        g_assert_cmpint (v1, ==, v2); // will fail
 *   For that, we often to use !! to coerce gboolean values to 0 or 1:
 *        g_assert_cmpint (!!v2, ==, TRUE);
 *   With _Bool type, this will be handled properly by the compiler.
 *
 * - For structs, we might want to safe even more space and use bitfields:
 *       struct s1 {
 *           gboolean v1:1;
 *       };
 *   But the problem here is that gboolean is signed, so that
 *   v1 will be either 0 or -1 (not 1, TRUE). Thus, the following
 *   fails:
 *      struct s1 s = { .v1 = TRUE, };
 *      g_assert_cmpint (s1.v1, ==, TRUE);
 *   It will however work just fine with bool/_Bool while retaining the
 *   notion of having a boolean value.
 *
 * Also, add the defines for "true" and "false". Those are nicely highlighted by the editor
 * as special types, contrary to glib's "TRUE"/"FALSE".
 */

#ifndef bool
#define bool _Bool
#define true    1
#define false   0
#endif

/*****************************************************************************/

#endif /* __NM_DEFAULT_H__ */
