/*
 * Copyright (C) 2013-2023 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef OC_VPN_H
#define OC_VPN_H

#include <config.h>
#include <gnutls/gnutls.h>
#include <llhttp.h>
#include <ccan/htable/htable.h>
#include <ccan/list/list.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <auth/common.h>

#include <ipc.pb-c.h>

#ifdef __GNUC__
#define _OCSERV_GCC_VERSION \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if _OCSERV_GCC_VERSION >= 30000
#define _ATTR_PACKED __attribute__((__packed__))
#endif
#endif /* __GNUC__ */

#ifndef _ATTR_PACKED
#define _ATTR_PACKED
#endif

#define MAX_MSG_SIZE 16 * 1024
#define DTLS_PROTO_INDICATOR "PSK-NEGOTIATE"

typedef enum { SOCK_TYPE_TCP, SOCK_TYPE_UDP, SOCK_TYPE_UNIX } sock_type_t;

typedef enum {
	OC_COMP_NULL = 0,
	OC_COMP_LZ4,
	OC_COMP_LZS,
} comp_type_t;

typedef enum fw_proto_t {
	PROTO_UDP,
	PROTO_TCP,
	PROTO_SCTP,
	PROTO_ESP,
	PROTO_ICMP,
	PROTO_ICMPv6,

	/* fix proto2str below if anything is added */
	PROTO_MAX
} fw_proto_t;

inline static const char *proto_to_str(fw_proto_t proto)
{
	const char *proto2str[] = { "udp", "tcp",  "sctp",
				    "esp", "icmp", "icmpv6" };

	if ((int)proto < 0 || proto >= PROTO_MAX)
		return "unknown";
	return proto2str[proto];
}

#define DEFAULT_LOG_LEVEL 2

/* Banning works with a point system. A wrong password
 * attempt gives you PASSWORD_POINTS, and you are banned
 * when the maximum ban score is reached.
 */
#define DEFAULT_PASSWORD_POINTS 10
#define DEFAULT_CONNECT_POINTS 1
#define DEFAULT_KKDCP_POINTS 1
#define DEFAULT_MAX_BAN_SCORE 80
#define DEFAULT_BAN_TIME 300
#define DEFAULT_BAN_RESET_TIME 1200

#define MIN_NO_COMPRESS_LIMIT 64
#define DEFAULT_NO_COMPRESS_LIMIT 256

/* The time after which a user will be forced to authenticate
 * or disconnect. */
#define DEFAULT_AUTH_TIMEOUT_SECS 240

/* The time after a disconnection the cookie is valid */
#define DEFAULT_COOKIE_RECON_TIMEOUT 300

#define DEFAULT_KEEPALIVE_TIME 32400
#define DEFAULT_REKEY_TIME 172800
#define DEFAULT_SWITCH_TO_TCP_TIMEOUT 25

#define DEFAULT_DPD_TIME 90
#define DEFAULT_MOBILE_DPD_TIME 1800

#define AC_PKT_DATA 0 /* Uncompressed data */
#define AC_PKT_DPD_OUT 3 /* Dead Peer Detection */
#define AC_PKT_DPD_RESP 4 /* DPD response */
#define AC_PKT_DISCONN 5 /* Client disconnection notice */
#define AC_PKT_KEEPALIVE 7 /* Keepalive */
#define AC_PKT_COMPRESSED 8 /* Compressed data */
#define AC_PKT_TERM_SERVER 9 /* Server kick */

#define REKEY_METHOD_SSL 1
#define REKEY_METHOD_NEW_TUNNEL 2

/* the first is generic, for the methods that require a username password */
#define AUTH_TYPE_USERNAME_PASS (1 << 0)
#define AUTH_TYPE_PAM (1 << 1 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_PLAIN (1 << 2 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_CERTIFICATE (1 << 3)
#define AUTH_TYPE_RADIUS (1 << 5 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_GSSAPI (1 << 6)
#define AUTH_TYPE_OIDC (1 << 7)

#define ALL_AUTH_TYPES                                              \
	((AUTH_TYPE_PAM | AUTH_TYPE_PLAIN | AUTH_TYPE_CERTIFICATE | \
	  AUTH_TYPE_RADIUS | AUTH_TYPE_GSSAPI | AUTH_TYPE_OIDC) &   \
	 (~AUTH_TYPE_USERNAME_PASS))
#define VIRTUAL_AUTH_TYPES (AUTH_TYPE_USERNAME_PASS)
#define CONFIDENTIAL_USER_NAME_AUTH_TYPES (AUTH_TYPE_GSSAPI | AUTH_TYPE_OIDC)

#define ACCT_TYPE_PAM (1 << 1)
#define ACCT_TYPE_RADIUS (1 << 2)

#include "defs.h"

/* Allow few seconds prior to cleaning up entries, to avoid any race
 * conditions when session control is enabled, as well as to allow
 * anyconnect clients to reconnect (they often drop the connection and
 * re-establish using the same cookie).
 */
#define AUTH_SLACK_TIME 15

#define MAX_CIPHERSUITE_NAME 64
#define SID_SIZE 32

struct vpn_st {
	char name[IFNAMSIZ];
	char *ipv4_netmask;
	char *ipv4_network;
	char *ipv4;
	char *ipv4_local; /* local IPv4 address */
	char *ipv6_network;
	unsigned int ipv6_prefix;

	char *ipv6;
	char *ipv6_local; /* local IPv6 address */
	unsigned int mtu;
	unsigned int ipv6_subnet_prefix; /* ipv6 subnet prefix to assign */

	char **routes;
	size_t routes_size;

	/* excluded routes */
	char **no_routes;
	size_t no_routes_size;

	char **dns;
	size_t dns_size;

	char **nbns;
	size_t nbns_size;
};

#define MAX_AUTH_METHODS 4
#define MAX_KRB_REALMS 16

typedef struct auth_struct_st {
	char *name;
	char *additional;
	unsigned int type;
	const struct auth_mod_st *amod;
	void *auth_ctx;
	void *dl_ctx;

	bool enabled;
} auth_struct_st;

typedef struct acct_struct_st {
	const char *name;
	char *additional;
	void *acct_ctx;
	const struct acct_mod_st *amod;
} acct_struct_st;

typedef struct kkdcp_realm_st {
	char *realm;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
} kkdcp_realm_st;

typedef struct kkdcp_st {
	char *url;
	/* the supported realms by this URL */
	kkdcp_realm_st realms[MAX_KRB_REALMS];
	unsigned int realms_size;
} kkdcp_st;

/*
 * Scope tags for config options:
 *   [scope: global]         -- reloadable; error if set in a [vhost:X] section
 *   [scope: vhost]          -- reloadable; can differ per virtual host
 *   [scope: vhost user]    -- reloadable; settable per-vhost and overridable per-user/group
 * Options in perm_cfg_st are permanent (require restart); see tags there.
 */
struct cfg_st {
	unsigned int is_dyndns; /* [scope: vhost] */
	unsigned int listen_proxy_proto; /* [scope: global] */
	unsigned int stats_report_time; /* [scope: vhost user] */

	kkdcp_st *kkdcp; /* [scope: vhost] */
	unsigned int kkdcp_size; /* [scope: vhost] */

	char *cert_user_oid; /* [scope: vhost] The OID that will be used to extract the username */
	char *cert_group_oid; /* [scope: vhost] The OID that will be used to extract the groupname */

	gnutls_certificate_request_t cert_req; /* [scope: vhost] */
	char *priorities; /* [scope: vhost] */
#ifdef ENABLE_COMPRESSION
	unsigned int enable_compression; /* [scope: vhost] */
	unsigned int
		no_compress_limit; /* [scope: vhost] under this size (in bytes) of data there will be no compression */
#endif
	char *banner; /* [scope: vhost] */
	char *pre_login_banner; /* [scope: vhost] */
	char *ocsp_response; /* [scope: vhost] file with the OCSP response */
	char *default_domain; /* [scope: vhost] domain to be advertised */

	char **group_list; /* [scope: vhost] select_group */
	unsigned int group_list_size; /* [scope: vhost] */

	char **friendly_group_list; /* [scope: vhost] the same size as group_list_size */

	unsigned int select_group_by_url; /* [scope: vhost] */
	unsigned int auto_select_group; /* [scope: vhost] */
	char *default_select_group; /* [scope: vhost] */

	char **custom_header; /* [scope: vhost] */
	size_t custom_header_size; /* [scope: vhost] */

	char **split_dns; /* [scope: vhost user] */
	size_t split_dns_size; /* [scope: vhost user] */

	/* http headers to include */
	char **included_http_headers; /* [scope: vhost] */
	size_t included_http_headers_size; /* [scope: vhost] */

	unsigned int
		append_routes; /* [scope: vhost] whether to append global routes to per-user config */
	unsigned int
		restrict_user_to_routes; /* [scope: vhost user] whether the firewall script will be run for the user */
	unsigned int
		deny_roaming; /* [scope: vhost user] whether a cookie is restricted to a single IP */
	time_t cookie_timeout; /* [scope: vhost] in seconds */
	time_t session_timeout; /* [scope: vhost user] in seconds */
	unsigned int
		persistent_cookies; /* [scope: vhost] whether cookies stay valid after disconnect */

	time_t rekey_time; /* [scope: vhost] in seconds */
	unsigned int rekey_method; /* [scope: vhost] REKEY_METHOD_ */

	time_t ban_time; /* [scope: global] duration IP remains banned after hitting max_ban_score -> in seconds */
	unsigned int
		max_ban_score; /* [scope: global] the score allowed before a user is banned (see vpn.h) */
	int ban_reset_time; /* [scope: global] */

	unsigned int ban_points_wrong_password; /* [scope: global] */
	unsigned int ban_points_connect; /* [scope: global] */
	unsigned int ban_points_kkdcp; /* [scope: global] */

	/* when using the new PSK DTLS negotiation make sure that
	 * the negotiated DTLS cipher/mac matches the TLS cipher/mac. */
	unsigned int match_dtls_and_tls; /* [scope: vhost] */
	unsigned int dtls_psk; /* [scope: global] whether to enable DTLS-PSK */
	unsigned int
		dtls_legacy; /* [scope: vhost] whether to enable DTLS-LEGACY */

	unsigned int
		isolate; /* [scope: global] whether seccomp should be enabled or not */

	unsigned int auth_timeout; /* [scope: global] timeout of HTTP auth */
	unsigned int idle_timeout; /* [scope: vhost user] timeout when idle */
	unsigned int
		mobile_idle_timeout; /* [scope: vhost user] timeout when a mobile is idle */
	unsigned int
		switch_to_tcp_timeout; /* [scope: vhost] length of no traffic period to automatically switch to TCP */
	unsigned int keepalive; /* [scope: vhost user] */
	unsigned int dpd; /* [scope: vhost user] */
	unsigned int mobile_dpd; /* [scope: vhost user] */
	unsigned int max_clients; /* [scope: global] */
	unsigned int max_same_clients; /* [scope: vhost user] */
	unsigned int use_utmp; /* [scope: global] */
	unsigned int tunnel_all_dns; /* [scope: vhost user] */
	unsigned int
		use_occtl; /* [scope: global] whether support for the occtl tool will be enabled */

	unsigned int try_mtu; /* [scope: global] MTU discovery enabled */
	unsigned int
		cisco_client_compat; /* [scope: vhost] do not require client certificate,
				       * and allow auth to complete in different
				       * TCP sessions. */
	unsigned int
		cisco_svc_client_compat; /* [scope: vhost] force allowed ciphers and disable dtls-legacy */
	unsigned int
		rate_limit_ms; /* [scope: global] if non zero force a connection every rate_limit milliseconds if ocserv-sm is heavily loaded */
	unsigned int
		ping_leases; /* [scope: global] non zero if we need to ping prior to leasing */
	unsigned int
		server_drain_ms; /* [scope: global] how long to wait after we stop accepting new connections before closing old connections */

	size_t rx_per_sec; /* [scope: vhost user] */
	size_t tx_per_sec; /* [scope: vhost user] */
	unsigned int net_priority; /* [scope: vhost user] */

	char *crl; /* [scope: vhost] */

	unsigned int output_buffer; /* [scope: vhost] */
	unsigned int default_mtu; /* [scope: vhost user] */
	unsigned int predictable_ips; /* [scope: vhost] boolean */

	char *route_add_cmd; /* [scope: global] */
	char *route_del_cmd; /* [scope: global] */

	char *connect_script; /* [scope: global] */
	char *host_update_script; /* [scope: global] */
	char *disconnect_script; /* [scope: global] */

	char *cgroup; /* [scope: vhost user] */
	char *proxy_url; /* [scope: vhost] */

#ifdef ANYCONNECT_CLIENT_COMPAT
	char *xml_config_file; /* [scope: vhost user] */
	char *xml_config_hash; /* [scope: vhost user] */
#endif

	unsigned int client_bypass_protocol; /* [scope: vhost user] */

	/* additional configuration files */
	char *per_group_dir; /* [scope: vhost] */
	char *per_user_dir; /* [scope: vhost] */
	char *default_group_conf; /* [scope: vhost] */
	char *default_user_conf; /* [scope: vhost] */

	bool gssapi_no_local_user_map; /* [scope: vhost] */

	/* known iroutes - only sent to the users who are not registering them */
	char **known_iroutes; /* [scope: vhost] */
	size_t known_iroutes_size; /* [scope: vhost] */

	FwPortSt **fw_ports; /* [scope: vhost user] */
	size_t n_fw_ports; /* [scope: vhost user] */

	/* the tun network */
	struct vpn_st
		network; /* [scope: vhost user] dns/routes/network sub-fields */

	/* holds a usage count of holders of pointers in this struct */
	int *usage_count; /* [scope: vhost] */

	bool camouflage; /* [scope: vhost] */
	char *camouflage_secret; /* [scope: vhost] */
	char *camouflage_realm; /* [scope: vhost] */

	bool no_udp; /* [scope: vhost user] */
};

/*
 * Permanent config (perm_cfg_st): requires server restart to change.
 * Scope tags:
 *   [scope: global (non-reloadable)] -- cannot differ per virtual host
 *   [scope: vhost (non-reloadable)]  -- can differ per virtual host
 */
struct perm_cfg_st {
	/* gets reloaded */
	struct cfg_st *config;

	/* stuff here don't change on reload */
	auth_struct_st
		auth[MAX_AUTH_METHODS]; /* [scope: vhost (non-reloadable)] */
	unsigned int auth_methods; /* [scope: vhost (non-reloadable)] */
	acct_struct_st acct; /* [scope: vhost (non-reloadable)] */
	unsigned int
		sup_config_type; /* [scope: vhost (non-reloadable)] one of SUP_CONFIG_ */

	char *chroot_dir; /* [scope: global (non-reloadable)] where the xml files are served from */
	char *occtl_socket_file; /* [scope: global (non-reloadable)] */
	char *socket_file_prefix; /* [scope: global (non-reloadable)] */

	uid_t uid; /* [scope: global (non-reloadable)] */
	gid_t gid; /* [scope: global (non-reloadable)] */

	char *key_pin; /* [scope: vhost (non-reloadable)] */
	char *srk_pin; /* [scope: vhost (non-reloadable)] */

	char *pin_file; /* [scope: vhost (non-reloadable)] */
	char *srk_pin_file; /* [scope: vhost (non-reloadable)] */
	char **cert; /* [scope: vhost (non-reloadable)] */
	size_t cert_size; /* [scope: vhost (non-reloadable)] */
	char **key; /* [scope: vhost (non-reloadable)] */
	size_t key_size; /* [scope: vhost (non-reloadable)] */
#ifdef ANYCONNECT_CLIENT_COMPAT
	char *cert_hash; /* [scope: vhost (non-reloadable)] */
#endif
	unsigned int stats_reset_time; /* [scope: global (non-reloadable)] */
	unsigned int foreground; /* [scope: global (non-reloadable)] */
	unsigned int no_chdir; /* [scope: global (non-reloadable)] */
	unsigned int log_level; /* [scope: global (non-reloadable)] */
	unsigned int log_stderr; /* [scope: global (non-reloadable)] */
	unsigned int syslog; /* [scope: global (non-reloadable)] */

	unsigned int pr_dumpable; /* [scope: global (non-reloadable)] */

	char *ca; /* [scope: vhost (non-reloadable)] */
	char *dh_params_file; /* [scope: vhost (non-reloadable)] */

	char *listen_host; /* [scope: global (non-reloadable)] */
	char *udp_listen_host; /* [scope: global (non-reloadable)] */
	char *listen_netns_name; /* [scope: global (non-reloadable)] */
	unsigned int port; /* [scope: global (non-reloadable)] */
	unsigned int udp_port; /* [scope: global (non-reloadable)] */

	unsigned int sec_mod_scale; /* [scope: global (non-reloadable)] */

	/* for testing ocserv only */
	unsigned int debug_no_secmod_stats; /* [scope: global (non-reloadable)] */

	/* attic, where old config allocated values are stored */
	struct list_head attic;
};

typedef struct attic_entry_st {
	struct list_node list;
	int *usage_count;
} attic_entry_st;

/* generic thing to stop complaints */
struct worker_st;
struct main_server_st;
struct dtls_st;

#define MAX_BANNER_SIZE 256
#define MAX_USERNAME_SIZE 64
#define MAX_AGENT_NAME 64
#define MAX_DEVICE_TYPE 64
#define MAX_DEVICE_PLATFORM 64
#define MAX_PASSWORD_SIZE 64
#define TLS_MASTER_SIZE 48
#define MAX_HOSTNAME_SIZE MAX_USERNAME_SIZE
#define MAX_GROUPNAME_SIZE MAX_USERNAME_SIZE
#define MAX_SESSION_DATA_SIZE (4 * 1024)

#if defined(CAPTURE_LATENCY_SUPPORT)
#define LATENCY_SAMPLE_SIZE 1024
#define LATENCY_WORKER_AGGREGATION_TIME 60
#endif

#define DEFAULT_CONFIG_ENTRIES 96

#include <tun.h>

unsigned int extract_prefix(char *network);

/* macros */
#define TOS_PACK(x) (x << 4)
#define TOS_UNPACK(x) (x >> 4)
#define IS_TOS(x) ((x & 0x0f) == 0)

/* Helper structures */
enum option_types {
	OPTION_NUMERIC,
	OPTION_STRING,
	OPTION_BOOLEAN,
	OPTION_MULTI_LINE
};

#include <ip-util.h>

void reload_cfg_file(void *pool, struct list_head *configs,
		     unsigned int sec_mod);
void clear_old_configs(struct list_head *configs);
void write_pid_file(void);
void remove_pid_file(void);

unsigned int switch_comp_priority(void *pool, const char *modstring);

extern sigset_t sig_default_set;

#endif
