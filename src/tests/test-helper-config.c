/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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

#include <string.h>
#include <stdlib.h>

#include "src/nm-openvpn-service.h"
#include "src/helper-config.h"

/******************************************************************/
/* libnm-util still uses GValueArray... remove when porting to libnm */

#ifdef __clang__

#undef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#undef G_GNUC_END_IGNORE_DEPRECATIONS

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic pop")

#endif

#define g_value_array_get_type() \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_get_type (); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_get_nth(value_array, index_) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_get_nth (value_array, index_); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

/******************************************************************/

/* returns argv */
static char **
load_config (const char *file)
{
	char *contents = NULL;
	gboolean success;
	GError *error = NULL;
	char **lines, **iter;
	char **argv = NULL;

	g_assert (file);
	success = g_file_get_contents (file, &contents, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (contents && contents[0]);

	lines = g_strsplit_set (contents, "\r\n", -1);
	g_assert (g_strv_length (lines) > 5);

	clearenv ();
	for (iter = lines; iter && *iter; iter++) {
		if (!argv) {
			argv = g_strsplit_set (*iter, " \t", -1);
			g_assert (argv && g_strv_length (argv));
		} else {
			g_assert (!*iter[0] || strchr (*iter, '='));
			putenv (*iter);
		}
	}

	return argv;
}

/********************/
/* Remove these when porting to libnm */

#define NM_UTILS_INET_ADDRSTRLEN     INET6_ADDRSTRLEN

static char _nm_utils_inet_ntop_buffer[NM_UTILS_INET_ADDRSTRLEN];

/**
 * nm_utils_inet4_ntop: (skip)
 * @inaddr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least %INET_ADDRSTRLEN
 *  or %NM_UTILS_INET_ADDRSTRLEN characters. If set to %NULL, it will return
 *  a pointer to an internal, static buffer (shared with nm_utils_inet6_ntop()).
 *  Beware, that the internal buffer will be overwritten with ever new call
 *  of nm_utils_inet4_ntop() or nm_utils_inet6_ntop() that does not provied it's
 *  own @dst buffer. Also, using the internal buffer is not thread safe. When
 *  in doubt, pass your own @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. This function cannot fail.
 **/
static const char *
nm_utils_inet4_ntop (in_addr_t inaddr, char *dst)
{
	return inet_ntop (AF_INET, &inaddr, dst ? dst : _nm_utils_inet_ntop_buffer,
	                  INET_ADDRSTRLEN);
}

/**
 * nm_utils_inet6_ntop: (skip)
 * @in6addr: the address that should be converted to string.
 * @dst: the destination buffer, it must contain at least %INET6_ADDRSTRLEN
 *  or %NM_UTILS_INET_ADDRSTRLEN characters. If set to %NULL, it will return
 *  a pointer to an internal, static buffer (shared with nm_utils_inet4_ntop()).
 *  Beware, that the internal buffer will be overwritten with ever new call
 *  of nm_utils_inet4_ntop() or nm_utils_inet6_ntop() that does not provied it's
 *  own @dst buffer. Also, using the internal buffer is not thread safe. When
 *  in doubt, pass your own @dst buffer to avoid these issues.
 *
 * Wrapper for inet_ntop.
 *
 * Returns: the input buffer @dst, or a pointer to an
 *  internal, static buffer. %NULL is not allowed as @in6addr,
 *  otherwise, this function cannot fail.
 **/
static const char *
nm_utils_inet6_ntop (const struct in6_addr *in6addr, char *dst)
{
	g_return_val_if_fail (in6addr, NULL);
	return inet_ntop (AF_INET6, in6addr, dst ? dst : _nm_utils_inet_ntop_buffer,
	                  INET6_ADDRSTRLEN);
}

/**********************/

typedef enum {
	OPT_TYPE_STRING,
	OPT_TYPE_UINT,
	OPT_TYPE_BOOLEAN,
	OPT_TYPE_IP4_ADDR,
	OPT_TYPE_IP4_ARRAY,
	OPT_TYPE_ROUTES4_ARRAY,
	OPT_TYPE_IP6_ADDR,
	OPT_TYPE_ROUTES6_ARRAY,
} OptType;

static GType
opt_type_to_gtype (OptType t)
{
	switch (t) {
	case OPT_TYPE_STRING:
		return G_TYPE_STRING;
	case OPT_TYPE_UINT:
		return G_TYPE_UINT;
	case OPT_TYPE_BOOLEAN:
		return G_TYPE_BOOLEAN;
	case OPT_TYPE_IP4_ADDR:
		return G_TYPE_UINT;
	case OPT_TYPE_IP6_ADDR:
		return DBUS_TYPE_G_UCHAR_ARRAY;
	case OPT_TYPE_IP4_ARRAY:
		return DBUS_TYPE_G_ARRAY_OF_UINT;
	case OPT_TYPE_ROUTES4_ARRAY:
		return DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT;
	case OPT_TYPE_ROUTES6_ARRAY:
		return DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE;
	}
	g_assert_not_reached ();
}

typedef struct {
	const char *name;
	OptType type;
	union {
		const char *s;        /* string, ipv4, ipv6 address */
		guint u;              /* uint and boolean */
		const char *sarray[6];
	} u;
} Option;

static void
config_equal (const Option *options, GHashTable *config)
{
	guint i = 0;
	const Option *expected;

	for (expected = options; expected->name; expected++, i++) {
		GValue *val = g_hash_table_lookup (config, expected->name);

		g_assert (val);
		g_assert (G_VALUE_HOLDS (val, opt_type_to_gtype (expected->type)));

		switch (expected->type) {
		case OPT_TYPE_STRING:
			g_assert_cmpstr (expected->u.s, ==, g_value_get_string (val));
			break;
		case OPT_TYPE_UINT:
			g_assert_cmpint (expected->u.u, ==, g_value_get_uint (val));
			break;
		case OPT_TYPE_BOOLEAN:
			g_assert_cmpint (!!expected->u.u, ==, g_value_get_boolean (val));
			break;
		case OPT_TYPE_IP4_ADDR:
			g_assert_cmpstr (expected->u.s, ==, nm_utils_inet4_ntop (g_value_get_uint (val), NULL));
			break;
		case OPT_TYPE_IP6_ADDR: {
			GByteArray *ba = g_value_get_boxed (val);

			g_assert_cmpint (ba->len, ==, sizeof (struct in6_addr));
			g_assert_cmpstr (expected->u.s, ==, nm_utils_inet6_ntop ((struct in6_addr *) ba->data, NULL));
			break;
		}
		case OPT_TYPE_IP4_ARRAY: {
			GArray *a = g_value_get_boxed (val);
			guint n;

			g_assert_cmpint (g_strv_length ((char **) expected->u.sarray), ==, a->len);
			for (n = 0; n < a->len; n++)
				g_assert_cmpstr (expected->u.sarray[n], ==, nm_utils_inet4_ntop (g_array_index (a, guint, n), NULL));
			break;
		}
		case OPT_TYPE_ROUTES4_ARRAY: {
			GPtrArray *a = g_value_get_boxed (val);
			GString *s = g_string_sized_new (30);
			guint n;

			g_assert_cmpint (g_strv_length ((char **) expected->u.sarray), ==, a->len);
			for (n = 0; n < a->len; n++) {
				GArray *r = g_ptr_array_index (a, n);

				g_string_set_size (s, 0);
				g_string_append_printf (s, "%s/%u",
				                        nm_utils_inet4_ntop (g_array_index (r, guint, 0), NULL),
				                        g_array_index (r, guint, 1));
				/* Split due to static buffer in nm_utils_inet4_ntop() */
				g_string_append_printf (s, ",%s,%u",
				                        nm_utils_inet4_ntop (g_array_index (r, guint, 2), NULL),
				                        g_array_index (r, guint, 3));

				g_assert_cmpstr (expected->u.sarray[n], ==, s->str);
			}
			g_string_free (s, TRUE);
			break;
		}
		case OPT_TYPE_ROUTES6_ARRAY: {
			GPtrArray *a = g_value_get_boxed (val);
			GString *s = g_string_sized_new (30);
			guint n;

			g_assert_cmpint (g_strv_length ((char **) expected->u.sarray), ==, a->len);
			for (n = 0; n < a->len; n++) {
				GValueArray *r = g_ptr_array_index (a, n);
				GByteArray *b;

				g_string_set_size (s, 0);

				b = g_value_get_boxed (g_value_array_get_nth (r, 0));
				g_assert_cmpint (b->len, ==, 16);
				g_string_append_printf (s, "%s/%u",
				                        nm_utils_inet6_ntop ((struct in6_addr *) b->data, NULL),
				                        g_value_get_uint (g_value_array_get_nth (r, 1)));

				/* Split due to static buffer in nm_utils_inet6_ntop() */
				b = g_value_get_boxed (g_value_array_get_nth (r, 2));
				g_assert_cmpint (b->len, ==, 16);
				g_string_append_printf (s, ",%s,%u",
				                        nm_utils_inet6_ntop ((struct in6_addr *) b->data, NULL),
				                        g_value_get_uint (g_value_array_get_nth (r, 3)));

				g_assert_cmpstr (expected->u.sarray[n], ==, s->str);
			}
			g_string_free (s, TRUE);
			break;
		}
		default:
			g_assert_not_reached ();
		}
	}

	g_assert_cmpint (i, ==, g_hash_table_size (config));
}

static void
test_init (void)
{
	gboolean success;
	char **argv;
	GError *error = NULL;
	GHashTable *config = NULL;
	GHashTable *ip4_config = NULL;
	GHashTable *ip6_config = NULL;
	const Option options[] = {
		{ NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, OPT_TYPE_IP4_ADDR, { .s = "87.238.35.145" } },
		{ NM_VPN_PLUGIN_CONFIG_TUNDEV,      OPT_TYPE_STRING,   { .s = "tun0"} },
		{ NM_VPN_PLUGIN_CONFIG_MTU,         OPT_TYPE_UINT,     { .u = 1500 } },
		{ NM_VPN_PLUGIN_CONFIG_HAS_IP4,     OPT_TYPE_BOOLEAN,  { .u = TRUE } },
		{ NM_VPN_PLUGIN_CONFIG_HAS_IP6,     OPT_TYPE_BOOLEAN,  { .u = TRUE } },
		{ NULL }
	};
	const Option ip4_options[] = {
		{ NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, OPT_TYPE_IP4_ADDR,      { .s = "100.64.48.5" } },
		{ NM_VPN_PLUGIN_IP4_CONFIG_PTP,         OPT_TYPE_IP4_ADDR,      { .s = "100.64.48.5" } },
		{ NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,     OPT_TYPE_IP4_ADDR,      { .s = "100.64.48.6" } },
		{ NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,      OPT_TYPE_UINT,          { .u = 32 } },
		{ NM_VPN_PLUGIN_IP4_CONFIG_DNS,         OPT_TYPE_IP4_ARRAY,     { .sarray = { "8.8.8.8", NULL } } },
		{ NM_VPN_PLUGIN_IP4_CONFIG_ROUTES,      OPT_TYPE_ROUTES4_ARRAY, { .sarray = { "10.0.0.0/24,100.64.48.5,0", "100.64.48.1/32,100.64.48.5,0", NULL } } },
		{ NULL }
	};
	const Option ip6_options[] = {
		{ NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS,     OPT_TYPE_IP6_ADDR,      { .s = "2001:db8::1000" } },
		{ NM_VPN_PLUGIN_IP6_CONFIG_PTP,         OPT_TYPE_IP6_ADDR,      { .s = "2001:db8::1" } },
		{ NM_VPN_PLUGIN_IP6_CONFIG_PREFIX,      OPT_TYPE_UINT,          { .u = 64 } },
		{ NM_VPN_PLUGIN_IP6_CONFIG_ROUTES,      OPT_TYPE_ROUTES6_ARRAY, { .sarray = { "fd00::/64,2001:db8::1,0", NULL } } },
		{ NULL }
	};

	argv = load_config (TESTDIR "/test-basic-init.conf");
	g_assert (argv);
	success = helper_generate_config ((const char **) argv, FALSE, FALSE, &config, &ip4_config, &ip6_config, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (config);
	config_equal (options, config);

	g_assert (ip4_config);
	config_equal (ip4_options, ip4_config);

	g_assert (ip6_config);
	config_equal (ip6_options, ip6_config);

	g_hash_table_unref (config);
	g_hash_table_unref (ip4_config);
	g_hash_table_unref (ip6_config);
	g_strfreev (argv);
}

#if 0
static void
test_restart (void)
{
	gboolean success;
	char **argv;
	GError *error = NULL;
	GHashTable *config = NULL;
	GHashTable *ip4_config = NULL;
	GHashTable *ip6_config = NULL;

	argv = load_config (TESTDIR "/test-basic-restart.conf");
	g_assert (argv);
	success = helper_generate_config ((const char **) argv, FALSE, TRUE, &config, &ip4_config, &ip6_config, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_hash_table_unref (config);
	g_hash_table_unref (ip4_config);
	g_hash_table_unref (ip6_config);
	g_strfreev (argv);
}
#endif

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_add_func ("/helper-config/init", test_init);
#if 0
	g_test_add_func ("/helper-config/restart", test_restart);
#endif

	return g_test_run ();
}

