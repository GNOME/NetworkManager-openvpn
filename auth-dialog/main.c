/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#include "nm-default.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gtk/gtk.h>

#include <libsecret/secret.h>

#include <nma-vpn-password-dialog.h>

#include "utils.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ KEYRING_UUID_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SN_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SK_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

#define UI_KEYFILE_GROUP "VPN Plugin UI"

typedef struct {
	const char *key;
	const char *label;
	const char *label_acc;
	char *existing;
	char *new;
	gboolean needed;
} Field;

typedef enum {
	FIELD_TYPE_PASSWORD,
	FIELD_TYPE_CERT_PASSWORD,
	FIELD_TYPE_PROXY_PASSWORD,
	_FIELD_TYPE_NUM,
} FieldType;

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GHashTable *attrs;
	GList *list;
	char *secret = NULL;

	attrs = secret_attributes_build (&network_manager_secret_schema,
	                                 KEYRING_UUID_TAG, uuid,
	                                 KEYRING_SN_TAG, NM_SETTING_VPN_SETTING_NAME,
	                                 KEYRING_SK_TAG, secret_name,
	                                 NULL);

	list = secret_service_search_sync (NULL, &network_manager_secret_schema, attrs,
	                                   SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
	                                   NULL, NULL);
	if (list && list->data) {
		SecretItem *item = list->data;
		SecretValue *value = secret_item_get_secret (item);

		if (value) {
			secret = g_strdup (secret_value_get (value, NULL));
			secret_value_unref (value);
		}
	}

	g_list_free_full (list, g_object_unref);
	g_hash_table_unref (attrs);
	return secret;
}

/*****************************************************************/

typedef void (*NoSecretsRequiredFunc) (void);

/* Returns TRUE on success, FALSE on cancel */
typedef gboolean (*AskUserFunc) (const char *vpn_name,
                                 const char *prompt,
                                 Field *fields);

typedef void (*FinishFunc) (const char *vpn_name,
                            const char *prompt,
                            gboolean allow_interaction,
                            Field *fields);

/*****************************************************************/
/* External UI mode stuff */

static void
keyfile_add_entry_info (GKeyFile    *keyfile,
                        const gchar *key,
                        const gchar *value,
                        const gchar *label,
                        gboolean     is_secret,
                        gboolean     should_ask)
{
	g_key_file_set_string (keyfile, key, "Value", value);
	g_key_file_set_string (keyfile, key, "Label", label);
	g_key_file_set_boolean (keyfile, key, "IsSecret", is_secret);
	g_key_file_set_boolean (keyfile, key, "ShouldAsk", should_ask);
}

static void
keyfile_print_stdout (GKeyFile *keyfile)
{
	gchar *data;
	gsize length;

	data = g_key_file_to_data (keyfile, &length, NULL);

	fputs (data, stdout);

	g_free (data);
}

static void
eui_no_secrets_required (void)
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	keyfile_add_entry_info (keyfile, NM_OPENVPN_KEY_NOSECRET, "true", "", TRUE, FALSE);
	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

static void
eui_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            Field *fields)
{
	Field *field;
	GKeyFile *keyfile;
	char *title;
	guint i;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);

	title = g_strdup_printf (_("Authenticate VPN %s"), vpn_name);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", title);
	g_free (title);

	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		field = &fields[i];
		keyfile_add_entry_info (keyfile,
		                        field->key,
		                        field->existing ?: "",
		                        _(field->label),
		                        TRUE,
		                        field->needed && allow_interaction);
	}

	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

/*****************************************************************/

static void
std_no_secrets_required (void)
{
	printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
}

static gboolean
std_ask_user (const char *vpn_name, const char *prompt, Field *fields)
{
	Field *field;
	NMAVpnPasswordDialog *dialog;
	gboolean success = FALSE;
	guint i;

	g_return_val_if_fail (vpn_name, FALSE);
	g_return_val_if_fail (prompt, FALSE);

	dialog = NMA_VPN_PASSWORD_DIALOG (nma_vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));

	/* pre-fill dialog with existing passwords */
	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		field = &fields[i];
		nma_vpn_password_dialog_field_set_visible (dialog, i, field->needed, TRUE);
		if (field->needed) {
			nma_vpn_password_dialog_field_set_label (dialog, i, _(field->label_acc));
			nma_vpn_password_dialog_field_set_text (dialog, i, field->existing);
		}
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	if (nma_vpn_password_dialog_run_and_block (dialog)) {
		for (i = 0; i < _FIELD_TYPE_NUM; i++) {
			if (fields[i].needed)
				fields[i].new = g_strdup (nma_vpn_password_dialog_field_get_text (dialog, i));
		}
		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));
	return success;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

static void
std_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            Field *fields)
{
	guint i;

	/* Send the passwords back to our parent */
	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		if (fields[i].new || fields[i].existing)
			printf ("%s\n%s\n", fields[i].key, fields[i].new ?: fields[i].existing);
	}

	printf ("\n\n");

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();
}

/*****************************************************************/

static gboolean
get_existing_passwords (GHashTable *vpn_data,
                        GHashTable *existing_secrets,
                        const char *vpn_uuid,
                        Field *fields)
{
	gboolean ret = FALSE;
	guint i;

	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

		if (!fields[i].needed)
			continue;

		nm_vpn_service_plugin_get_secret_flags (vpn_data, fields[i].key, &flags);
		if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED) {
			ret = TRUE;
			continue;
		}

		fields[i].existing = g_strdup (g_hash_table_lookup (existing_secrets, fields[i].key));
		if (!fields[i].existing)
			fields[i].existing = keyring_lookup_secret (vpn_uuid, fields[i].key);
		if (!fields[i].existing)
			ret = TRUE;
	}

	return ret;
}

#define VPN_MSG_TAG "x-vpn-message:"

static gboolean
get_passwords_required (GHashTable *data,
                        const char *const *hints,
                        char **prompt,
                        Field *fields)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags;
	const char *const *iter;
	guint i;

	/* If hints are given, then always ask for what the hints require */
	if (hints) {
		for (iter = hints; iter && *iter; iter++) {
			if (!*prompt && g_str_has_prefix (*iter, VPN_MSG_TAG))
				*prompt = g_strdup (*iter + strlen (VPN_MSG_TAG));
			else {
				for (i = 0; i < _FIELD_TYPE_NUM; i++) {
					if (nm_streq (*iter, fields[i].key))
						fields[i].needed = TRUE;
				}
			}
		}
		goto done;
	}

	ctype = g_hash_table_lookup (data, NM_OPENVPN_KEY_CONNECTION_TYPE);
	g_return_val_if_fail (ctype, FALSE);

	if (NM_IN_STRSET (ctype,
	                  NM_OPENVPN_CONTYPE_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Normal user password */
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (   nm_streq (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
		    && !(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			fields[FIELD_TYPE_PASSWORD].needed = TRUE;

		/* Encrypted private key password */
		val = g_hash_table_lookup (data, NM_OPENVPN_KEY_KEY);
		if (val)
			fields[FIELD_TYPE_CERT_PASSWORD].needed = is_encrypted (val);
	} else if (nm_streq (ctype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			fields[FIELD_TYPE_PASSWORD].needed = TRUE;
	}

	val = g_hash_table_lookup (data, NM_OPENVPN_KEY_PROXY_SERVER);
	if (val && val[0]) {
		flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_vpn_service_plugin_get_secret_flags (data, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			fields[FIELD_TYPE_PROXY_PASSWORD].needed = TRUE;
	}

done:
	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		if (fields[i].needed)
			return TRUE;
	}

	return FALSE;
}

static void
clear_secrets (Field **fields)
{
	guint i;

	for (i = 0; i < _FIELD_TYPE_NUM; i++) {
		nm_free_secret ((*fields)[i].existing);
		nm_free_secret ((*fields)[i].new);
	}
}

int
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	gs_unref_hashtable GHashTable *data_hash = NULL;
	gs_unref_hashtable GHashTable *secrets_hash = NULL;
	gs_strfreev char **hints = NULL;
	gs_free char *prompt = NULL;
	gboolean needed = FALSE;
	gboolean external_ui_mode = FALSE;
	gboolean ask_user;
	NoSecretsRequiredFunc no_secrets_required_func;
	AskUserFunc ask_user_func;
	FinishFunc finish_func;
	Field fields[] = {
		[FIELD_TYPE_PASSWORD] = {
			.key = NM_OPENVPN_KEY_PASSWORD,
			.label = N_("Password:"),
			.label_acc = N_("_Password:"),
		},
		[FIELD_TYPE_CERT_PASSWORD] = {
			.key = NM_OPENVPN_KEY_CERTPASS,
			.label = N_("Certificate password:"),
			.label_acc = N_("Certificate pass_word:"),
		},
		[FIELD_TYPE_PROXY_PASSWORD] = {
			.key = NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
			.label = N_("HTTP proxy password"),
			.label_acc = N_("_HTTP proxy password:"),
		},
	};
	nm_auto(clear_secrets) Field *_fields = fields;

	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
			{ "hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &hints, "Hints from the VPN plugin", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- openvpn auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		return EXIT_FAILURE;
	}

	if (strcmp (vpn_service, NM_VPN_SERVICE_TYPE_OPENVPN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_VPN_SERVICE_TYPE_OPENVPN);
		return EXIT_FAILURE;
	}

	if (!nm_vpn_service_plugin_read_vpn_details (0, &data_hash, &secrets_hash)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return EXIT_FAILURE;
	}

	if (external_ui_mode) {
		no_secrets_required_func = eui_no_secrets_required;
		ask_user_func = NULL;
		finish_func = eui_finish;
	} else {
		no_secrets_required_func = std_no_secrets_required;
		ask_user_func = std_ask_user;
		finish_func = std_finish;
	}

	/* Determine which passwords are actually required, either from hints or
	 * from looking at the VPN configuration.
	 */
	needed = get_passwords_required (data_hash, (const char *const*) hints, &prompt, fields);
	if (!prompt)
		prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network “%s”."), vpn_name);

	/* Exit early if we don't need any passwords */
	if (!needed) {
		no_secrets_required_func ();
		return EXIT_SUCCESS;
	}

	ask_user = get_existing_passwords (data_hash,
	                                   secrets_hash,
	                                   vpn_uuid,
	                                   fields);

	/* If interaction is allowed then ask the user, otherwise pass back
	 * whatever existing secrets we can find.
	 */
	if (   ask_user_func
	    && allow_interaction
	    && (ask_user || retry)) {
		if (!ask_user_func (vpn_name, prompt, fields))
			return EXIT_FAILURE;
	}

	finish_func (vpn_name,
	             prompt,
	             allow_interaction,
	             fields);

	return EXIT_SUCCESS;
}
