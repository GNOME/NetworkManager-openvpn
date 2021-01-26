/*
 * network-manager-openvpn - OpenVPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * Copyright (C) 2010 - 2018 Red Hat, Inc.
 */

#ifndef UTILS_H
#define UTILS_H

#define NMV_OVPN_TAG_ALLOW_PULL_FQDN        "allow-pull-fqdn"
#define NMV_OVPN_TAG_AUTH                   "auth"
#define NMV_OVPN_TAG_AUTH_NOCACHE           "auth-nocache"
#define NMV_OVPN_TAG_NCP_DISABLE            "ncp-disable"
#define NMV_OVPN_TAG_AUTH_USER_PASS         "auth-user-pass"
#define NMV_OVPN_TAG_CA                     "ca"
#define NMV_OVPN_TAG_CERT                   "cert"
#define NMV_OVPN_TAG_CIPHER                 "cipher"
#define NMV_OVPN_TAG_CLIENT                 "client"
#define NMV_OVPN_TAG_COMP_LZO               "comp-lzo"
#define NMV_OVPN_TAG_COMPRESS               "compress"
#define NMV_OVPN_TAG_CONNECT_TIMEOUT        "connect-timeout"
#define NMV_OVPN_TAG_CRL_VERIFY             "crl-verify"
#define NMV_OVPN_TAG_DEV                    "dev"
#define NMV_OVPN_TAG_DEV_TYPE               "dev-type"
#define NMV_OVPN_TAG_EXTRA_CERTS            "extra-certs"
#define NMV_OVPN_TAG_FLOAT                  "float"
#define NMV_OVPN_TAG_FRAGMENT               "fragment"
#define NMV_OVPN_TAG_GROUP                  "group"
#define NMV_OVPN_TAG_HTTP_PROXY             "http-proxy"
#define NMV_OVPN_TAG_HTTP_PROXY_RETRY       "http-proxy-retry"
#define NMV_OVPN_TAG_IFCONFIG               "ifconfig"
#define NMV_OVPN_TAG_KEEPALIVE              "keepalive"
#define NMV_OVPN_TAG_KEY                    "key"
#define NMV_OVPN_TAG_KEYSIZE                "keysize"
#define NMV_OVPN_TAG_KEY_DIRECTION          "key-direction"
#define NMV_OVPN_TAG_MAX_ROUTES             "max-routes"
#define NMV_OVPN_TAG_MSSFIX                 "mssfix"
#define NMV_OVPN_TAG_MTU_DISC               "mtu-disc"
#define NMV_OVPN_TAG_NOBIND                 "nobind"
#define NMV_OVPN_TAG_NS_CERT_TYPE           "ns-cert-type"
#define NMV_OVPN_TAG_PERSIST_KEY            "persist-key"
#define NMV_OVPN_TAG_PERSIST_TUN            "persist-tun"
#define NMV_OVPN_TAG_PING                   "ping"
#define NMV_OVPN_TAG_PING_EXIT              "ping-exit"
#define NMV_OVPN_TAG_PING_RESTART           "ping-restart"
#define NMV_OVPN_TAG_PKCS12                 "pkcs12"
#define NMV_OVPN_TAG_PORT                   "port"
#define NMV_OVPN_TAG_PROTO                  "proto"
#define NMV_OVPN_TAG_PUSH_PEER_INFO         "push-peer-info"
#define NMV_OVPN_TAG_REMOTE                 "remote"
#define NMV_OVPN_TAG_REMOTE_CERT_TLS        "remote-cert-tls"
#define NMV_OVPN_TAG_REMOTE_RANDOM          "remote-random"
#define NMV_OVPN_TAG_REMOTE_RANDOM_HOSTNAME "remote-random-hostname"
#define NMV_OVPN_TAG_RENEG_SEC              "reneg-sec"
#define NMV_OVPN_TAG_ROUTE                  "route"
#define NMV_OVPN_TAG_RPORT                  "rport"
#define NMV_OVPN_TAG_SCRIPT_SECURITY        "script-security"
#define NMV_OVPN_TAG_SECRET                 "secret"
#define NMV_OVPN_TAG_SERVER_POLL_TIMEOUT    "server-poll-timeout"
#define NMV_OVPN_TAG_SOCKS_PROXY            "socks-proxy"
#define NMV_OVPN_TAG_SOCKS_PROXY_RETRY      "socks-proxy-retry"
#define NMV_OVPN_TAG_TLS_AUTH               "tls-auth"
#define NMV_OVPN_TAG_TLS_CIPHER             "tls-cipher"
#define NMV_OVPN_TAG_TLS_CLIENT             "tls-client"
#define NMV_OVPN_TAG_TLS_CRYPT              "tls-crypt"
#define NMV_OVPN_TAG_TLS_CRYPT_V2           "tls-crypt-v2"
#define NMV_OVPN_TAG_TLS_REMOTE             "tls-remote"
#define NMV_OVPN_TAG_TLS_VERSION_MIN        "tls-version-min"
#define NMV_OVPN_TAG_TLS_VERSION_MAX        "tls-version-max"
#define NMV_OVPN_TAG_TOPOLOGY               "topology"
#define NMV_OVPN_TAG_TUN_IPV6               "tun-ipv6"
#define NMV_OVPN_TAG_TUN_MTU                "tun-mtu"
#define NMV_OVPN_TAG_USER                   "user"
#define NMV_OVPN_TAG_VERIFY_X509_NAME       "verify-x509-name"

typedef enum {
	NMOVPN_COMP_DISABLED,             /* no option */
	NMOVPN_COMP_LZO,                  /* "--compress lzo" or "--comp-lzo yes" */
	NMOVPN_COMP_LZ4,                  /* "--compress lz4" */
	NMOVPN_COMP_LZ4_V2,               /* "--compress lz4-v2" */
	NMOVPN_COMP_AUTO,                 /* "--compress" */
	NMOVPN_COMP_LEGACY_LZO_DISABLED,  /* "--comp-lzo no" */
	NMOVPN_COMP_LEGACY_LZO_ADAPTIVE,  /* "--comp-lzo [adaptive]" */
} NMOvpnComp;

gboolean is_pkcs12 (const char *filepath);

gboolean is_encrypted (const char *filename);

#define NMOVPN_PROTCOL_TYPES \
	"udp", \
	"udp4", \
	"udp6", \
	"tcp", \
	"tcp4", \
	"tcp6", \
	"tcp-client", \
	"tcp4-client", \
	"tcp6-client"

gssize nmovpn_remote_parse (const char *str,
                            char **out_buf,
                            const char **out_host,
                            const char **out_port,
                            const char **out_proto,
                            GError **error);

static inline const char *
nmovpn_arg_is_set (const char *value)
{
	return (value && value[0]) ? value : NULL;
}

NMOvpnComp nmovpn_compression_from_options (const char *comp_lzo,
                                            const char *compress);
void nmovpn_compression_to_options (NMOvpnComp comp,
                                    const char **comp_lzo,
                                    const char **compress);

#endif  /* UTILS_H */
