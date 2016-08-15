/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
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

#include "nm-default.h"

#include "auth-helpers.h"

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

#define BLOCK_HANDLER_ID "block-handler-id"

static void
show_password (GtkToggleButton *togglebutton, GtkEntry *password_entry)
{
	gtk_entry_set_visibility (password_entry, gtk_toggle_button_get_active (togglebutton));
}

static GtkWidget *
setup_secret_widget (GtkBuilder *builder,
                     const char *widget_name,
                     NMSettingVpn *s_vpn,
                     const char *secret_key)
{
	GtkWidget *widget;
	GtkWidget *show_passwords;
	const char *tmp;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
	g_assert (widget);

	show_passwords = GTK_WIDGET (gtk_builder_get_object (builder, "show_passwords"));
	g_signal_connect (show_passwords, "toggled", G_CALLBACK (show_password), widget);

	if (s_vpn) {
		tmp = nm_setting_vpn_get_secret (s_vpn, secret_key);
		if (tmp)
			gtk_entry_set_text (GTK_ENTRY (widget), tmp);
	}

	return widget;
}

typedef struct {
	GtkWidget *widget1;
	GtkWidget *widget2;
} TlsChooserSignalData;

static void
tls_chooser_signal_data_destroy (gpointer data, GClosure *closure)
{
	g_slice_free (TlsChooserSignalData, data);
}

static void
tls_cert_changed_cb (GtkWidget *widget, gpointer data)
{
	GtkWidget *other_widgets[2] = { ((TlsChooserSignalData *) data)->widget1,
	                                ((TlsChooserSignalData *) data)->widget2 };
	GtkFileChooser *this = GTK_FILE_CHOOSER (widget);
	char *fname, *dirname, *tmp;
	int i;

	/* If the just-changed file chooser is a PKCS#12 file, then all of the
	 * TLS filechoosers have to be PKCS#12.  But if it just changed to something
	 * other than a PKCS#12 file, then clear out the other file choosers.
	 *
	 * Basically, all the choosers have to contain PKCS#12 files, or none of
	 * them can, because PKCS#12 files contain everything required for the TLS
	 * connection (CA, client cert, private key).
	 */

	fname = gtk_file_chooser_get_filename (this);
	dirname = g_path_get_dirname (fname);

	for (i = 0; i < G_N_ELEMENTS (other_widgets); i++) {
		GtkFileChooser *other = GTK_FILE_CHOOSER (other_widgets[i]);
		char *other_fname = gtk_file_chooser_get_filename (other);
		gulong id = GPOINTER_TO_SIZE (g_object_get_data (G_OBJECT (other), BLOCK_HANDLER_ID));

		g_signal_handler_block (other, id);
		if (is_pkcs12 (fname)) {
			/* Make sure all choosers have this PKCS#12 file */
			if (!other_fname || strcmp (fname, other_fname))
				gtk_file_chooser_set_filename (other, fname);
		} else {
			/* Just-chosen file isn't PKCS#12 or no file was chosen, so clear out other
			 * file selectors that have PKCS#12 files in them.
			 */
			if (is_pkcs12 (other_fname))
				gtk_file_chooser_unselect_all (other);

			/* Set directory of un-set file choosers to the directory just selected */
			tmp = gtk_file_chooser_get_filename (other);
			if (!tmp && dirname)
				gtk_file_chooser_set_current_folder (other, dirname);
			g_free (tmp);
		}
		g_signal_handler_unblock (other, id);
		g_free (other_fname);
	}

	g_free (fname);
	g_free (dirname);
}

static void
tls_setup (GtkBuilder *builder,
           GtkSizeGroup *group,
           NMSettingVpn *s_vpn,
           const char *prefix,
           GtkWidget *ca_chooser,
           ChangedCallback changed_cb,
           gpointer user_data)
{
	GtkWidget *widget, *cert, *key;
	const char *value;
	char *tmp;
	GtkFileFilter *filter;
	TlsChooserSignalData *ca_chooser_data, *cert_data, *key_data;
	gulong id1, id2, id3;

	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
	cert = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	gtk_size_group_add_widget (group, cert);
	filter = tls_file_chooser_filter_new (TRUE);
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (cert), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (cert), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (cert),
	                                   _("Choose your personal certificate..."));
	g_signal_connect (G_OBJECT (cert), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (cert), value);
	}

	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
	key = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	gtk_size_group_add_widget (group, key);
	filter = tls_file_chooser_filter_new (TRUE);
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (key), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (key), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (key),
	                                   _("Choose your private key..."));
	g_signal_connect (G_OBJECT (key), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (key), value);
	}

	ca_chooser_data = g_slice_new0 (TlsChooserSignalData);
	ca_chooser_data->widget1 = cert;
	ca_chooser_data->widget2 = key;
	cert_data = g_slice_new0 (TlsChooserSignalData);
	cert_data->widget1 = ca_chooser;
	cert_data->widget2 = key;
	key_data = g_slice_new0 (TlsChooserSignalData);
	key_data->widget1 = ca_chooser;
	key_data->widget2 = cert;

	/* Link choosers to the PKCS#12 changer callback */
	id1 = g_signal_connect_data (ca_chooser, "selection-changed", G_CALLBACK (tls_cert_changed_cb),
	                             ca_chooser_data, tls_chooser_signal_data_destroy, 0);
	id2 = g_signal_connect_data (cert, "selection-changed", G_CALLBACK (tls_cert_changed_cb),
	                             cert_data, tls_chooser_signal_data_destroy, 0);
	id3 = g_signal_connect_data (key, "selection-changed", G_CALLBACK (tls_cert_changed_cb),
	                             key_data, tls_chooser_signal_data_destroy, 0);

	/* Store handler id to be able to block the signal in tls_cert_changed_cb() */
	g_object_set_data (G_OBJECT (ca_chooser), BLOCK_HANDLER_ID, GSIZE_TO_POINTER (id1));
	g_object_set_data (G_OBJECT (cert), BLOCK_HANDLER_ID, GSIZE_TO_POINTER (id2));
	g_object_set_data (G_OBJECT (key), BLOCK_HANDLER_ID, GSIZE_TO_POINTER (id3));

	/* Fill in the private key password */
	tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
	widget = setup_secret_widget (builder, tmp, s_vpn, NM_OPENVPN_KEY_CERTPASS);
	g_free (tmp);
	gtk_size_group_add_widget (group, widget);
	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);

	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_vpn, NM_OPENVPN_KEY_CERTPASS,
	                                  TRUE, FALSE);
}

static void
pw_setup (GtkBuilder *builder,
          GtkSizeGroup *group,
          NMSettingVpn *s_vpn,
          const char *prefix,
          ChangedCallback changed_cb,
          gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	char *tmp;

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);
	gtk_size_group_add_widget (group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	/* Fill in the user password */
	tmp = g_strdup_printf ("%s_password_entry", prefix);
	widget = setup_secret_widget (builder, tmp, s_vpn, NM_OPENVPN_KEY_PASSWORD);
	g_free (tmp);
	gtk_size_group_add_widget (group, widget);
	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);

	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_vpn, NM_OPENVPN_KEY_PASSWORD,
	                                  TRUE, FALSE);
}

void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         GtkSizeGroup *group,
                         NMSettingVpn *s_vpn,
                         const char *contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *ca;
	const char *value;
	char *tmp;
	GtkFileFilter *filter;
	gboolean tls = FALSE, pw = FALSE;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	ca = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);
	gtk_size_group_add_widget (group, ca);

	/* Three major connection types here: TLS-only, PW-only, and TLS + PW */
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		tls = TRUE;
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		pw = TRUE;

	/* Only TLS types can use PKCS#12 */
	filter = tls_file_chooser_filter_new (tls);

	/* Set up CA cert file picker which all connection types support */
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (ca), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (ca), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (ca),
	                                   _("Choose a Certificate Authority certificate..."));
	g_signal_connect (G_OBJECT (ca), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (ca), value);
	}

	/* Set up the rest of the options */
	if (tls)
		tls_setup (builder, group, s_vpn, prefix, ca, changed_cb, user_data);
	if (pw)
		pw_setup (builder, group, s_vpn, prefix, changed_cb, user_data);
}

#define SK_DIR_COL_NAME 0
#define SK_DIR_COL_NUM  1

void
sk_init_auth_widget (GtkBuilder *builder,
                     GtkSizeGroup *group,
                     NMSettingVpn *s_vpn,
                     ChangedCallback changed_cb,
                     gpointer user_data)
{
	GtkWidget *widget;
	const char *value = NULL;
	GtkListStore *store;
	GtkTreeIter iter;
	gint active = -1;
	gint direction = -1;
	GtkFileFilter *filter;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
	gtk_size_group_add_widget (group, widget);
	filter = sk_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose an OpenVPN static key..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
		if (value && strlen (value)) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && (tmp == 0 || tmp == 1))
				direction = (guint32) tmp;
		}
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, _("None"), SK_DIR_COL_NUM, -1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "0", SK_DIR_COL_NUM, 0, -1);
	if (direction == 0)
		active = 1;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "1", SK_DIR_COL_NUM, 1, -1);
	if (direction == 1)
		active = 2;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
	gtk_size_group_add_widget (group, widget);

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
	gtk_size_group_add_widget (group, widget);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
	gtk_size_group_add_widget (group, widget);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
}

static gboolean
validate_file_chooser (GtkBuilder *builder, const char *name)
{
	GtkWidget *widget;
	char *str;
	gboolean valid = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, name));
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		valid = TRUE;
	g_free (str);
	return valid;
}

static gboolean
validate_tls (GtkBuilder *builder, const char *prefix, GError **error)
{
	char *tmp;
	gboolean valid, encrypted = FALSE;
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	gboolean secrets_required = TRUE;

	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	valid = validate_file_chooser (builder, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_CA);
		return FALSE;
	}

	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
	valid = validate_file_chooser (builder, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_CERT);
		return FALSE;
	}

	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	valid = validate_file_chooser (builder, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_KEY);
		return FALSE;
	}

	/* Encrypted certificates require a password */
	tmp = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	encrypted = is_encrypted (tmp);
	g_free (tmp);

	tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);
	pw_flags = nma_utils_menu_to_secret_flags (widget);
	if (   pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
	    || pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		secrets_required = FALSE;

	if (encrypted && secrets_required) {
		if (!gtk_entry_get_text_length (GTK_ENTRY (widget))) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_CERTPASS);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error)
{
	GtkWidget *widget;
	const char *str;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		if (!validate_tls (builder, "tls", error))
			return FALSE;
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		if (!validate_tls (builder, "pw_tls", error))
			return FALSE;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_tls_username_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		if (!validate_file_chooser (builder, "pw_ca_cert_chooser")) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_CA);
			return FALSE;
		}
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "pw_username_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		if (!validate_file_chooser (builder, "sk_key_chooser")) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_STATIC_KEY);
			return FALSE;
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_LOCAL_IP);
			return FALSE;
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_REMOTE_IP);
			return FALSE;
		}
	} else
		g_assert_not_reached ();

	return TRUE;
}

static void
update_from_filechooser (GtkBuilder *builder,
                         const char *key,
                         const char *prefix,
                         const char *widget_name,
                         NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	char *tmp, *filename;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_%s", prefix, widget_name);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (filename && strlen (filename))
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
	g_free (filename);
}

static void
update_tls (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	const char *str;

	update_from_filechooser (builder, NM_OPENVPN_KEY_CA, prefix, "ca_cert_chooser", s_vpn);
	update_from_filechooser (builder, NM_OPENVPN_KEY_CERT, prefix, "user_cert_chooser", s_vpn);
	update_from_filechooser (builder, NM_OPENVPN_KEY_KEY, prefix, "private_key_chooser", s_vpn);

	/* Password */
	tmp = g_strdup_printf ("%s_private_key_password_entry", prefix);
	widget = (GtkWidget *) gtk_builder_get_object (builder, tmp);
	g_assert (widget);
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS, str);

	pw_flags = nma_utils_menu_to_secret_flags (widget);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_CERTPASS, pw_flags, NULL);
}

static void
update_pw (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	const char *str;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME, str);

	/* Password */
	tmp = g_strdup_printf ("%s_password_entry", prefix);
	widget = (GtkWidget *) gtk_builder_get_object (builder, tmp);
	g_assert (widget);
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, str);

	/* Update password flags */
	pw_flags = nma_utils_menu_to_secret_flags (widget);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, pw_flags, NULL);
}

gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;
	const char *str;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		update_tls (builder, "tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		update_from_filechooser (builder, NM_OPENVPN_KEY_CA, "pw", "ca_cert_chooser", s_vpn);
		update_pw (builder, "pw", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		update_tls (builder, "pw_tls", s_vpn);
		update_pw (builder, "pw_tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		/* Update static key */
		update_from_filechooser (builder, NM_OPENVPN_KEY_STATIC_KEY, "sk", "key_chooser", s_vpn);

		/* Update direction */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
		g_assert (widget);
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
		if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
			int direction = -1;

			gtk_tree_model_get (model, &iter, SK_DIR_COL_NUM, &direction, -1);
			if (direction > -1) {
				char *tmp = g_strdup_printf ("%d", direction);
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, tmp);
				g_free (tmp);
			}
		}

		/* Update local address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		g_assert (widget);
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, str);

		/* Update remote address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		g_assert (widget);
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, str);
	} else
		g_assert_not_reached ();

	return TRUE;
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_pkcs8_key_begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";
static const char *pem_unenc_key_begin = "-----BEGIN PRIVATE KEY-----";

static gboolean
tls_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	char *contents = NULL, *p, *ext;
	gsize bytes_read = 0;
	gboolean show = FALSE;
	gboolean pkcs_allowed = GPOINTER_TO_UINT (data);
	struct stat statbuf;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;

	if (pkcs_allowed && g_str_has_suffix (ext, ".p12") && is_pkcs12 (filter_info->filename)) {
		g_free (ext);
		return TRUE;
	}

	if (!g_str_has_suffix (ext, ".pem") && !g_str_has_suffix (ext, ".crt") &&
		!g_str_has_suffix (ext, ".key") && !g_str_has_suffix (ext, ".cer")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	/* Ignore files that are really large */
	if (!stat (filter_info->filename, &statbuf)) {
		if (statbuf.st_size > 500000)
			return FALSE;
	}

	if (!g_file_get_contents (filter_info->filename, &contents, &bytes_read, NULL))
		return FALSE;

	if (bytes_read < 400)  /* needs to be lower? */
		goto out;

	/* Check for PEM signatures */
	if (find_tag (pem_rsa_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_dsa_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_cert_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_pkcs8_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_unenc_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	g_free (contents);
	return show;
}

GtkFileFilter *
tls_file_chooser_filter_new (gboolean pkcs_allowed)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, tls_default_filter, GUINT_TO_POINTER (pkcs_allowed), NULL);
	gtk_file_filter_set_name (filter, pkcs_allowed ? _("PEM or PKCS#12 certificates (*.pem, *.crt, *.key, *.cer, *.p12)")
	                                               : _("PEM certificates (*.pem, *.crt, *.key, *.cer)"));
	return filter;
}


static const char *sk_key_begin = "-----BEGIN OpenVPN Static key V1-----";

static gboolean
sk_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	int fd;
	unsigned char buffer[1024];
	ssize_t bytes_read;
	gboolean show = FALSE;
	char *p;
	char *ext;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (!g_str_has_suffix (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	fd = open (filter_info->filename, O_RDONLY);
	if (fd < 0)
		return FALSE;

	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
	if (bytes_read < 400)  /* needs to be lower? */
		goto out;
	buffer[bytes_read] = '\0';

	/* Check for PEM signatures */
	if (find_tag (sk_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	close (fd);
	return show;
}

GtkFileFilter *
sk_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, sk_default_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("OpenVPN Static Keys (*.key)"));
	return filter;
}

static const char *advanced_keys[] = {
	NM_OPENVPN_KEY_PORT,
	NM_OPENVPN_KEY_COMP_LZO,
	NM_OPENVPN_KEY_MSSFIX,
	NM_OPENVPN_KEY_FLOAT,
	NM_OPENVPN_KEY_TUNNEL_MTU,
	NM_OPENVPN_KEY_FRAGMENT_SIZE,
	NM_OPENVPN_KEY_TAP_DEV,
	NM_OPENVPN_KEY_DEV,
	NM_OPENVPN_KEY_DEV_TYPE,
	NM_OPENVPN_KEY_PROTO_TCP,
	NM_OPENVPN_KEY_PROXY_TYPE,
	NM_OPENVPN_KEY_PROXY_SERVER,
	NM_OPENVPN_KEY_PROXY_PORT,
	NM_OPENVPN_KEY_PROXY_RETRY,
	NM_OPENVPN_KEY_HTTP_PROXY_USERNAME,
	NM_OPENVPN_KEY_CIPHER,
	NM_OPENVPN_KEY_KEYSIZE,
	NM_OPENVPN_KEY_AUTH,
	NM_OPENVPN_KEY_TA_DIR,
	NM_OPENVPN_KEY_TA,
	NM_OPENVPN_KEY_RENEG_SECONDS,
	NM_OPENVPN_KEY_TLS_REMOTE,
	NM_OPENVPN_KEY_REMOTE_RANDOM,
	NM_OPENVPN_KEY_TUN_IPV6,
	NM_OPENVPN_KEY_REMOTE_CERT_TLS,
	NM_OPENVPN_KEY_NS_CERT_TYPE,
	NM_OPENVPN_KEY_PING,
	NM_OPENVPN_KEY_PING_EXIT,
	NM_OPENVPN_KEY_PING_RESTART,
	NM_OPENVPN_KEY_MAX_ROUTES,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;

		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;
	const char *secret, *flags;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = nm_connection_get_setting_vpn (connection);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	/* HTTP Proxy password is special */
	secret = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
	if (secret) {
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD),
		                     g_strdup (secret));
	}
	flags = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags");
	if (flags)
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags"),
		                     g_strdup (flags));

	return hash;
}

static void
checkbox_toggled_update_widget_cb (GtkWidget *check, gpointer user_data)
{
	GtkWidget *widget = (GtkWidget*) user_data;

	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static const char *
nm_find_openvpn (void)
{
	static const char *openvpn_binary_paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		NULL
	};
	const char  **openvpn_binary = openvpn_binary_paths;

	while (*openvpn_binary != NULL) {
		if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
			break;
		openvpn_binary++;
	}

	return *openvpn_binary;
}

#define TLS_CIPHER_COL_NAME 0
#define TLS_CIPHER_COL_DEFAULT 1

static void
populate_cipher_combo (GtkComboBox *box, const char *user_cipher)
{
	GtkListStore *store;
	GtkTreeIter iter;
	const char *openvpn_binary = NULL;
	gchar *tmp, **items, **item;
	gboolean user_added = FALSE;
	char *argv[3];
	GError *error = NULL;
	gboolean success, found_blank = FALSE;

	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary)
		return;

	argv[0] = (char *) openvpn_binary;
	argv[1] = "--show-ciphers";
	argv[2] = NULL;

	success = g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, &tmp, NULL, NULL, &error);
	if (!success) {
		g_warning ("%s: couldn't determine ciphers: %s", __func__, error->message);
		g_error_free (error);
		return;
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --cipher to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, _("Default"),
	                    TLS_CIPHER_COL_DEFAULT, TRUE, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, "none",
	                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
	if (g_strcmp0 (user_cipher, "none") == 0) {
		gtk_combo_box_set_active_iter (box, &iter);
		user_added = TRUE;
	}

	items = g_strsplit (tmp, "\n", 0);
	g_free (tmp);

	for (item = items; *item; item++) {
		char *space = strchr (*item, ' ');

		/* Don't add anything until after the first blank line */
		if (!found_blank) {
			if (!strlen (*item))
				found_blank = TRUE;
			continue;
		}

		if (space)
			*space = '\0';

		if (strcmp (*item, "none") == 0)
			continue;

		if (strlen (*item)) {
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
			                    TLS_CIPHER_COL_NAME, *item,
			                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
			if (!user_added && user_cipher && !strcmp (*item, user_cipher)) {
				gtk_combo_box_set_active_iter (box, &iter);
				user_added = TRUE;
			}
		}
	}

	/* Add the user-specified cipher if it exists wasn't found by openvpn */
	if (user_cipher && !user_added) {
		gtk_list_store_insert (store, &iter, 1);
		gtk_list_store_set (store, &iter,
		                    TLS_CIPHER_COL_NAME, user_cipher,
		                    TLS_CIPHER_COL_DEFAULT, FALSE -1);
		gtk_combo_box_set_active_iter (box, &iter);
	} else if (!user_added) {
		gtk_combo_box_set_active (box, 0);
	}

	g_object_unref (G_OBJECT (store));
	g_strfreev (items);
}

#define HMACAUTH_COL_NAME 0
#define HMACAUTH_COL_VALUE 1
#define HMACAUTH_COL_DEFAULT 2

static void
populate_hmacauth_combo (GtkComboBox *box, const char *hmacauth)
{
	GtkListStore *store;
	GtkTreeIter iter;
	gboolean active_initialized = FALSE;
	const char **item;
	static const char *items[] = {
		NM_OPENVPN_AUTH_NONE,
		NM_OPENVPN_AUTH_RSA_MD4,
		NM_OPENVPN_AUTH_MD5,
		NM_OPENVPN_AUTH_SHA1,
		NM_OPENVPN_AUTH_SHA224,
		NM_OPENVPN_AUTH_SHA256,
		NM_OPENVPN_AUTH_SHA384,
		NM_OPENVPN_AUTH_SHA512,
		NM_OPENVPN_AUTH_RIPEMD160,
		NULL
	};

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --auth to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    HMACAUTH_COL_NAME, _("Default"),
	                    HMACAUTH_COL_DEFAULT, TRUE, -1);

	/* Add options */
	for (item = items; *item; item++) {
		const char *name = NULL;

		if (!strcmp (*item, NM_OPENVPN_AUTH_NONE))
			name = _("None");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_RSA_MD4))
			name = _("RSA MD-4");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_MD5))
			name = _("MD-5");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA1))
			name = _("SHA-1");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA224))
			name = _("SHA-224");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA256))
			name = _("SHA-256");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA384))
			name = _("SHA-384");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_SHA512))
			name = _("SHA-512");
		else if (!strcmp (*item, NM_OPENVPN_AUTH_RIPEMD160))
			name = _("RIPEMD-160");
		else
			g_assert_not_reached ();

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
		                    HMACAUTH_COL_NAME, name,
		                    HMACAUTH_COL_VALUE, *item,
		                    HMACAUTH_COL_DEFAULT, FALSE, -1);
		if (hmacauth && !strcmp (*item, hmacauth)) {
			gtk_combo_box_set_active_iter (box, &iter);
			active_initialized = TRUE;
		}
	}

	if (!active_initialized)
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

static void
remote_tls_cert_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_remote_cert_tls = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	use_remote_cert_tls = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_label"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);
}

#define REMOTE_CERT_COL_NAME 0
#define REMOTE_CERT_COL_VALUE 1

static void
populate_remote_cert_tls_combo (GtkComboBox *box, const char *remote_cert)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Server"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Client"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_CLIENT,
	                    -1);

	if (g_strcmp0 (remote_cert, NM_OPENVPN_REM_CERT_TLS_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

static void
tls_auth_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_auth = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_checkbutton"));
	use_auth = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_label"));
	gtk_widget_set_sensitive (widget, use_auth);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_label"));
	gtk_widget_set_sensitive (widget, use_auth);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
	gtk_widget_set_sensitive (widget, use_auth);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
	gtk_widget_set_sensitive (widget, use_auth);
}

static void
ns_cert_type_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_ns_cert_type = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	use_ns_cert_type = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_label"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);
}

#define NS_CERT_TYPE_COL_NAME 0
#define NS_CERT_TYPE_COL_VALUE 1

static void
populate_ns_cert_type_combo (GtkComboBox *box, const char *type)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Server"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Client"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_CLIENT,
	                    -1);

	if (g_strcmp0 (type, NM_OPENVPN_NS_CERT_TYPE_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

#define PROXY_TYPE_NONE  0
#define PROXY_TYPE_HTTP  1
#define PROXY_TYPE_SOCKS 2

#define DEVICE_TYPE_IDX_TUN     0
#define DEVICE_TYPE_IDX_TAP     1

#define PING_EXIT    0
#define PING_RESTART 1

static void
proxy_type_changed (GtkComboBox *combo, gpointer user_data)
{
	GtkBuilder *builder = GTK_BUILDER (user_data);
	gboolean sensitive;
	GtkWidget *widget;
	guint32 i = 0;
	int active;
	const char *widgets[] = {
		"proxy_desc_label", "proxy_server_label", "proxy_server_entry",
		"proxy_port_label", "proxy_port_spinbutton", "proxy_retry_checkbutton",
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};
	const char *user_pass_widgets[] = {
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};

	active = gtk_combo_box_get_active (combo);
	sensitive = (active > PROXY_TYPE_NONE);

	while (widgets[i]) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, widgets[i++]));
		gtk_widget_set_sensitive (widget, sensitive);
	}

	/* Additionally user/pass widgets need to be disabled for SOCKS */
	if (active == PROXY_TYPE_SOCKS) {
		i = 0;
		while (user_pass_widgets[i]) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, user_pass_widgets[i++]));
			gtk_widget_set_sensitive (widget, FALSE);
		}
	}

	/* Proxy options require TCP; but don't reset the TCP checkbutton
	 * to false when the user disables HTTP proxy; leave it checked.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (sensitive == TRUE)
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	gtk_widget_set_sensitive (widget, !sensitive);
}

static void
show_proxy_password_toggled_cb (GtkCheckButton *button, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;
	gboolean visible;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	g_assert (widget);

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
device_name_filter_cb (GtkEntry *entry,
                       const gchar *text,
                       gint length,
                       gint *position,
                       void *user_data)
{
	int i, count = 0;
	gchar *result = g_new (gchar, length + 1);
	GtkEditable *editable = GTK_EDITABLE (entry);

	for (i = 0; i < length; i++) {
		if (text[i] == '/' || g_ascii_isspace (text[i]))
			continue;
		result[count++] = text[i];
	}
	result[count] = 0;

	if (count > 0) {
		g_signal_handlers_block_by_func (G_OBJECT (editable),
		                                 G_CALLBACK (device_name_filter_cb),
		                                 user_data);
		gtk_editable_insert_text (editable, result, count, position);
		g_signal_handlers_unblock_by_func (G_OBJECT (editable),
		                                   G_CALLBACK (device_name_filter_cb),
		                                   user_data);
	}
	g_signal_stop_emission_by_name (G_OBJECT (editable), "insert-text");

	g_free (result);
}

static gboolean
device_name_changed_cb (GtkEntry *entry,
                        gpointer user_data)
{
	GtkEditable *editable = GTK_EDITABLE (entry);
	GtkWidget *ok_button = user_data;
	gboolean entry_sensitive;
	char *entry_text;
	GdkRGBA rgba;

	entry_sensitive = gtk_widget_get_sensitive (GTK_WIDGET (entry));
	entry_text = gtk_editable_get_chars (editable, 0, -1);

	/* Change cell's background to red if the value is invalid */
	if (entry_sensitive && entry_text[0] != '\0' && !nm_utils_iface_valid_name (entry_text)) {
		gdk_rgba_parse (&rgba, "red");
		gtk_widget_override_background_color (GTK_WIDGET (editable), GTK_STATE_FLAG_NORMAL, &rgba);
		gtk_widget_set_sensitive (ok_button, FALSE);
	} else {
		gtk_widget_override_background_color (GTK_WIDGET (editable), GTK_STATE_FLAG_NORMAL, NULL);
		gtk_widget_set_sensitive (ok_button, TRUE);
	}

	g_free (entry_text);
	return FALSE;
}

static void
dev_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *entry, *ok_button;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	/* Set values to default ones */
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check))) {
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), DEVICE_TYPE_IDX_TUN);
	}

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, entry);
	device_name_changed_cb (GTK_ENTRY (entry), ok_button);
}

static void
_builder_init_optional_spinbutton (GtkBuilder *builder,
                                   const char *checkbutton_name,
                                   const char *spinbutton_name,
                                   gboolean active_state,
                                   gint64 value)
{
	GtkWidget *widget;
	GtkWidget *spin;

	widget = (GtkWidget *) gtk_builder_get_object (builder, checkbutton_name);
	g_return_if_fail (GTK_IS_TOGGLE_BUTTON (widget));

	spin = (GtkWidget *) gtk_builder_get_object (builder, spinbutton_name);
	g_return_if_fail (GTK_IS_SPIN_BUTTON (spin));

	g_signal_connect ((GObject *) widget, "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	gtk_spin_button_set_value ((GtkSpinButton *) spin, (double) value);

	gtk_widget_set_sensitive (spin, active_state);
	gtk_toggle_button_set_active ((GtkToggleButton *) widget, active_state);
}

static void
ping_exit_restart_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *spin;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, spin);
}

#define TA_DIR_COL_NAME 0
#define TA_DIR_COL_NUM 1

GtkWidget *
advanced_dialog_new (GHashTable *hash, const char *contype)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	char *ui_file = NULL;
	GtkWidget *widget, *combo, *spin, *entry, *ok_button;
	const char *value, *value2;
	const char *dev, *dev_type, *tap_dev;
	GtkListStore *store;
	GtkTreeIter iter;
	guint32 active;
	guint32 pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-openvpn-dialog.ui");
	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (builder, ui_file, &error)) {
		g_warning ("Couldn't load builder file: %s", error->message);
		g_error_free (error);
		g_object_unref (G_OBJECT (builder));
		goto out;
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "openvpn-advanced-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		goto out;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "builder",
	                        builder, (GDestroyNotify) g_object_unref);
	g_object_set_data (G_OBJECT (dialog), "connection-type", GINT_TO_POINTER (contype));

	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (value && strlen (value)) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp >= 0 && tmp <= 604800) {  /* up to a week? */
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 0.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	/* Proxy support */
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not required"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("HTTP"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("SOCKS"), -1);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_SERVER);
	value2 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_PORT);
	if (value && strlen (value) && value2 && strlen (value2)) {
		long int tmp = 0;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		gtk_entry_set_text (GTK_ENTRY (widget), value);

		errno = 0;
		tmp = strtol (value2, NULL, 10);
		if (errno != 0 || tmp < 0 || tmp > 65535)
			tmp = 0;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_RETRY);
		if (value && !strcmp (value, "yes"))
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
			gtk_entry_set_text (GTK_ENTRY (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags");
		if (value && strlen (value)) {
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno != 0 || tmp < 0 || tmp > 65535)
				tmp = 0;
			pw_flags = (guint32) tmp;
		}
	}
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	nma_utils_setup_password_storage (widget, pw_flags, NULL, NULL,
	                                  TRUE, FALSE);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_TYPE);
	active = PROXY_TYPE_NONE;
	if (value) {
		if (!strcmp (value, "http"))
			active = PROXY_TYPE_HTTP;
		else if (!strcmp (value, "socks"))
			active = PROXY_TYPE_SOCKS;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);
	proxy_type_changed (GTK_COMBO_BOX (combo), builder);
	g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (proxy_type_changed), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "show_proxy_password"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (show_proxy_password_toggled_cb), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PORT);
	if (value && strlen (value)) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536 && tmp != 1194) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget),
			                           (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 1194.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	g_assert (widget);
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TUNNEL_MTU);
	if (value && strlen (value)) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 1500.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	if (value && strlen (value)) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp >= 0 && tmp < 65536) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 1300.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_COMP_LZO);
	if (NM_IN_STRSET (value, "yes", "adaptive")) {
		/* the UI currently only supports "--comp-lzo yes" or omitting the "--comp-lzo"
		 * flag.
		 *
		 * Internally, we also support "--comp-lzo [adaptive]" and "--comp-lzo no"
		 * which have different meaning for openvpn. */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "lzo_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MSSFIX);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "mssfix_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_FLOAT);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "float_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROTO_TCP);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	/* Populate device-related widgets */
	dev =      g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV);
	dev_type = g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV_TYPE);
	tap_dev =  g_hash_table_lookup (hash, NM_OPENVPN_KEY_TAP_DEV);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), (dev && *dev) || dev_type || tap_dev);
	dev_checkbox_toggled_cb (widget, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (dev_checkbox_toggled_cb), builder);
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	active = DEVICE_TYPE_IDX_TUN;
	if (   !g_strcmp0 (dev_type, "tap")
	    || (!dev_type && dev && g_str_has_prefix (dev, "tap"))
	    || (!dev_type && !g_strcmp0 (tap_dev, "yes")))
		active = DEVICE_TYPE_IDX_TAP;

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TUN"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TAP"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	gtk_entry_set_max_length (GTK_ENTRY (entry), 15);  /* interface name is max 15 chars */
	gtk_entry_set_placeholder_text (GTK_ENTRY (entry), _("(automatic)"));
	g_signal_connect (G_OBJECT (entry), "insert-text", G_CALLBACK (device_name_filter_cb), NULL);
	g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (device_name_changed_cb), ok_button);
	if (dev && dev[0] != '\0')
		gtk_entry_set_text (GTK_ENTRY (entry), dev);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_RANDOM);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_random_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TUN_IPV6);
	if (value && !strcmp (value, "yes")) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tun_ipv6_checkbutton"));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CIPHER);
	populate_cipher_combo (GTK_COMBO_BOX (widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_checkbutton"));
	g_assert (widget);
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_KEYSIZE);
	if (value && strlen (value)) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 128.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_AUTH);
	populate_hmacauth_combo (GTK_COMBO_BOX (widget), value);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_REMOTE);
	if (value && strlen (value)) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
		gtk_entry_set_text (GTK_ENTRY(widget), value);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	if (value && strlen (value))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_tls_cert_toggled_cb), builder);
	remote_tls_cert_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	populate_remote_cert_tls_combo (GTK_COMBO_BOX (widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	if (value && strlen (value))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ns_cert_type_toggled_cb), builder);
	ns_cert_type_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	populate_ns_cert_type_combo (GTK_COMBO_BOX (widget), value);

	if (   !strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		int direction = -1;

		active = 0;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_checkbutton"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA);
		if (value && strlen (value))
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (tls_auth_toggled_cb), builder);
		tls_auth_toggled_cb (widget, builder);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA_DIR);
		if (value && strlen (value)) {
			direction = (int) strtol (value, NULL, 10);
			/* If direction is not 0 or 1, use no direction */
			if (direction != 0 && direction != 1)
				direction = -1;
		}

		store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, _("None"), TA_DIR_COL_NUM, -1, -1);

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "0", TA_DIR_COL_NUM, 0, -1);
		if (direction == 0)
			active = 1;

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "1", TA_DIR_COL_NUM, 1, -1);
		if (direction == 1)
			active = 2;

		gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
		g_object_unref (store);
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active);

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA);
		if (value && strlen (value)) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
		}
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "options_notebook"));
		gtk_notebook_remove_page (GTK_NOTEBOOK (widget), 2);
	}

	/* ping */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING);
	if (value && *value) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 30.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	/* ping-exit / ping-restart */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	ping_exit_restart_checkbox_toggled_cb (widget, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ping_exit_restart_checkbox_toggled_cb), builder);

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_EXIT);
	if (value && *value)
		active = PING_EXIT;
	else {
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_RESTART);
		active = PING_RESTART;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-exit"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-restart"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);

	if (value && *value) {
		long int tmp;

		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 30.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MAX_ROUTES);
	_builder_init_optional_spinbutton (builder, "max_routes_checkbutton", "max_routes_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, 100000000, 100));


out:
	g_free (ui_file);
	return dialog;
}

GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash;
	GtkWidget *widget;
	GtkBuilder *builder;
	const char *contype = NULL;
	const char *value;
	int proxy_type = PROXY_TYPE_NONE;
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "builder");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int reneg_seconds;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
		reneg_seconds = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_RENEG_SECONDS), g_strdup_printf ("%d", reneg_seconds));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int tunmtu_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		tunmtu_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TUNNEL_MTU), g_strdup_printf ("%d", tunmtu_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int fragment_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
		fragment_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_FRAGMENT_SIZE), g_strdup_printf ("%d", fragment_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int port;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PORT), g_strdup_printf ("%d", port));
	}

	/* Proxy support */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));
	proxy_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	if (proxy_type != PROXY_TYPE_NONE) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && strlen (value)) {
			int proxy_port;

			if (proxy_type == PROXY_TYPE_HTTP)
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_TYPE), g_strdup ("http"));
			else if (proxy_type == PROXY_TYPE_SOCKS)
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_TYPE), g_strdup ("socks"));

			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_SERVER), g_strdup (value));

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
			proxy_port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
			if (proxy_port > 0) {
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_PORT),
				                     g_strdup_printf ("%d", proxy_port));
			}

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
			if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROXY_RETRY), g_strdup ("yes"));

			if (proxy_type == PROXY_TYPE_HTTP) {
				guint32 pw_flags;

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
				value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
				if (value && strlen (value)) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_USERNAME),
					                     g_strdup (value));
				}

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
				value = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
				if (value && strlen (value)) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD),
					                     g_strdup (value));
				}

				pw_flags = nma_utils_menu_to_secret_flags (widget);
				if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD"-flags"),
					                     g_strdup_printf ("%d", pw_flags));
				}
			}
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "lzo_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		/* we only have a checkbox, which we either map to "--comp-lzo yes" or
		 * no "--comp-lzo" flag. In the UI, we cannot express "--comp-lzo [adaptive]"
		 * or "--comp-lzo no".
		 *
		 * Note that "--comp-lzo no" must be encoded as "comp-lzo=no-by-default" (bgo#769177).
		 */
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_COMP_LZO), g_strdup ("yes"));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mssfix_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_MSSFIX), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "float_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_FLOAT), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_PROTO_TCP), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int device_type;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
		device_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_DEV_TYPE),
		                     g_strdup (device_type == DEVICE_TYPE_IDX_TUN ? "tun" : "tap"));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
		value = gtk_entry_get_text (GTK_ENTRY (widget));
		if (value && value[0] != '\0')
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_DEV), g_strdup (value));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_random_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_REMOTE_RANDOM), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tun_ipv6_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TUN_IPV6), g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		char *cipher = NULL;
		gboolean is_default = TRUE;

		gtk_tree_model_get (model, &iter,
		                    TLS_CIPHER_COL_NAME, &cipher,
		                    TLS_CIPHER_COL_DEFAULT, &is_default, -1);
		if (!is_default && cipher) {
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_CIPHER), g_strdup (cipher));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int keysize_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
		keysize_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_KEYSIZE), g_strdup_printf ("%d", keysize_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		char *hmacauth = NULL;
		gboolean is_default = TRUE;

		gtk_tree_model_get (model, &iter,
		                    HMACAUTH_COL_VALUE, &hmacauth,
		                    HMACAUTH_COL_DEFAULT, &is_default, -1);
		if (!is_default && hmacauth) {
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_AUTH), g_strdup (hmacauth));
		}
	}

	contype = g_object_get_data (G_OBJECT (dialog), "connection-type");
	if (   !strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
		value = gtk_entry_get_text (GTK_ENTRY(widget));
		if (value && strlen (value))
			g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TLS_REMOTE), g_strdup (value));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *remote_cert = NULL;

				gtk_tree_model_get (model, &iter, REMOTE_CERT_COL_VALUE, &remote_cert, -1);
				if (remote_cert)
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_REMOTE_CERT_TLS),
					                     remote_cert);
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *type = NULL;

				gtk_tree_model_get (model, &iter, NS_CERT_TYPE_COL_VALUE, &type, -1);
				if (type)
					g_hash_table_insert (hash,
					                     g_strdup (NM_OPENVPN_KEY_NS_CERT_TYPE),
					                     type);
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_checkbutton"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
			char *filename;

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
			if (filename && strlen (filename)) {
				g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TA), g_strdup (filename));
			}
			g_free (filename);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				int direction = -1;

				gtk_tree_model_get (model, &iter, TA_DIR_COL_NUM, &direction, -1);
				if (direction >= 0) {
					g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_TA_DIR),
					                     g_strdup_printf ("%d", direction));
				}
			}
		}
	}

        widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     g_strdup (NM_OPENVPN_KEY_PING),
		                     g_strdup_printf ("%d", ping_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int ping_exit_type, ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
		ping_exit_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     ping_exit_type == PING_EXIT ?
		                       g_strdup (NM_OPENVPN_KEY_PING_EXIT) :
		                       g_strdup (NM_OPENVPN_KEY_PING_RESTART),
		                     g_strdup_printf ("%d", ping_val));
	}

	/* max routes */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int max_routes;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_spinbutton"));
		max_routes = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_OPENVPN_KEY_MAX_ROUTES), g_strdup_printf ("%d", max_routes));
	}

	return hash;
}

