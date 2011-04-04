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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-vpn-plugin-utils.h>

#include "common-gnome/keyring-helpers.h"
#include "common/utils.h"
#include "src/nm-openvpn-service.h"
#include "gnome-two-password-dialog.h"

static gboolean
get_secrets (const char *vpn_name,
             const char *vpn_uuid,
             gboolean need_password,
             gboolean need_certpass,
             gboolean retry,
             gboolean allow_interaction,
             const char *in_pass,
             NMSettingSecretFlags pw_flags,
             char **out_password,
             const char *in_certpass,
             NMSettingSecretFlags cp_flags,
             char **out_certpass)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	char *prompt, *password = NULL, *certpass = NULL;
	gboolean success = FALSE, need_secret = FALSE;

	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (out_password != NULL, FALSE);
	g_return_val_if_fail (out_certpass != NULL, FALSE);

	if (need_password) {
		if (!(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			if (in_pass)
				password = gnome_keyring_memory_strdup (in_pass);
			else
				password = keyring_helpers_lookup_secret (vpn_uuid, NM_OPENVPN_KEY_PASSWORD, &is_session);
		}
		if (!password && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			need_secret = TRUE;
	}

	if (need_certpass) {
		if (!(cp_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			if (in_certpass)
				certpass = gnome_keyring_memory_strdup (in_certpass);
			else
				certpass = keyring_helpers_lookup_secret (vpn_uuid, NM_OPENVPN_KEY_CERTPASS, &is_session);
		}
		if (!certpass && !(cp_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			need_secret = TRUE;
	}

	/* Have all passwords and we're not supposed to ask the user again */
	if (!need_secret && !retry)
		return TRUE;

	if (allow_interaction == FALSE) {
		if (need_password)
			*out_password = password;
		if (need_certpass)
			*out_certpass = certpass;
		return TRUE;
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (password || certpass) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* pre-fill dialog with the password */
	if (need_password && need_certpass) {
		gnome_two_password_dialog_set_show_password_secondary (dialog, TRUE);
		gnome_two_password_dialog_set_password_secondary_label (dialog, _("Certificate pass_word:") );

		/* if retrying, put in the passwords from the keyring */
		if (password)
			gnome_two_password_dialog_set_password (dialog, password);
		if (certpass)
			gnome_two_password_dialog_set_password_secondary (dialog, certpass);
	} else {
		gnome_two_password_dialog_set_show_password_secondary (dialog, FALSE);
		if (need_password) {
			/* if retrying, put in the passwords from the keyring */
			if (password)
				gnome_two_password_dialog_set_password (dialog, password);
		} else if (need_certpass) {
			gnome_two_password_dialog_set_password_primary_label (dialog, _("Certificate password:"));
			/* if retrying, put in the passwords from the keyring */
			if (certpass)
				gnome_two_password_dialog_set_password (dialog, certpass);
		}
	}

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}
	if (certpass) {
		memset (certpass, 0, strlen (certpass));
		gnome_keyring_memory_free (certpass);
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		gboolean save = FALSE;
		char *keyring = NULL;

		if (need_password)
			*out_password = gnome_keyring_memory_strdup (gnome_two_password_dialog_get_password (dialog));
		if (need_certpass) {
			if (need_password)
				*out_certpass = gnome_keyring_memory_strdup (gnome_two_password_dialog_get_password_secondary (dialog));
			else
				*out_certpass = gnome_keyring_memory_strdup (gnome_two_password_dialog_get_password (dialog));
		}

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring = "session";
			/* Fall through */
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save = TRUE;
			break;
		default:
			break;
		}

		if (save) {
			if (*out_password) {
				keyring_helpers_save_secret (vpn_uuid, vpn_name, keyring,
											 NM_OPENVPN_KEY_PASSWORD, *out_password);
			}
			if (*out_certpass) {
				keyring_helpers_save_secret (vpn_uuid, vpn_name, keyring,
											 NM_OPENVPN_KEY_CERTPASS, *out_certpass);
			}
		}

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));

	return success;
}

static void
get_password_types (GHashTable *data,
                    gboolean *out_need_password,
                    gboolean *out_need_certpass)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	ctype = g_hash_table_lookup (data, NM_OPENVPN_KEY_CONNECTION_TYPE);
	g_return_if_fail (ctype != NULL);

	if (!strcmp (ctype, NM_OPENVPN_CONTYPE_TLS) || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Normal user password */
		nm_vpn_plugin_utils_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (   !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
		    && !(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;

		/* Encrypted private key password */
		val = g_hash_table_lookup (data, NM_OPENVPN_KEY_KEY);
		if (val)
			*out_need_certpass = is_encrypted (val);
	} else if (!strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		nm_vpn_plugin_utils_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;
	}
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

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	gboolean need_password = FALSE, need_certpass = FALSE;
	char *new_password = NULL, *new_certpass = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags cp_flags = NM_SETTING_SECRET_FLAG_NONE;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
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

	if (strcmp (vpn_service, NM_DBUS_SERVICE_OPENVPN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_OPENVPN);
		return EXIT_FAILURE;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	get_password_types (data, &need_password, &need_certpass);
	if (!need_password && !need_certpass) {
		printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
		return 0;
	}

	nm_vpn_plugin_utils_get_secret_flags (data, NM_OPENVPN_KEY_PASSWORD, &pw_flags);
	nm_vpn_plugin_utils_get_secret_flags (data, NM_OPENVPN_KEY_CERTPASS, &cp_flags);
	if (get_secrets (vpn_name,
	                 vpn_uuid,
	                 need_password,
	                 need_certpass,
	                 retry,
	                 allow_interaction,
	                 g_hash_table_lookup (secrets, NM_OPENVPN_KEY_PASSWORD),
	                 pw_flags,
	                 &new_password,
	                 g_hash_table_lookup (secrets, NM_OPENVPN_KEY_CERTPASS),
	                 cp_flags,
	                 &new_certpass)) {
		if (need_password && new_password)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_PASSWORD, new_password);
		if (need_certpass && new_certpass)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_CERTPASS, new_certpass);
	}
	printf ("\n\n");

	if (new_password) {
		memset (new_password, 0, strlen (new_password));
		gnome_keyring_memory_free (new_password);
	}
	if (new_certpass) {
		memset (new_certpass, 0, strlen (new_certpass));
		gnome_keyring_memory_free (new_certpass);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
