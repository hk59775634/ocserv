/*
 * Copyright (C) 2014-2016 Red Hat, Inc.
 * Copyright (C) 2016-2018 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vpn.h>
#include <ctype.h>
#include <arpa/inet.h> /* inet_ntop */
#include "radius.h"
#include "auth/common.h"
#include "str.h"
#include <ccan/hash/hash.h>

#ifdef HAVE_RADIUS

#include "common-config.h"

#ifdef LEGACY_RADIUS
#include <freeradius-client.h>
#else
#include <radcli/radcli.h>
#endif

#ifndef VENDOR_BIT_SIZE
#define VENDOR_BIT_SIZE 16
#define VENDOR_MASK 0xffff
#else
#define VENDOR_MASK 0xffffffff
#endif

#define VATTRID_SET(a, v) \
	((a) | ((uint64_t)((v) & VENDOR_MASK)) << VENDOR_BIT_SIZE)

#define RAD_GROUP_NAME PW_CLASS
/* Microsoft - RFC 2548 */
#define MS_PRIMARY_DNS_SERVER VATTRID_SET(28, 311)
#define MS_SECONDARY_DNS_SERVER VATTRID_SET(29, 311)
/* Roaring Penguin */
#define RP_UPSTREAM_SPEED_LIMIT VATTRID_SET(1, 10055)
#define RP_DOWNSTREAM_SPEED_LIMIT VATTRID_SET(2, 10055)

#if defined(LEGACY_RADIUS)
#ifndef PW_DELEGATED_IPV6_PREFIX
#define PW_DELEGATED_IPV6_PREFIX 123
#endif
#ifndef PW_ACCT_INTERIM_INTERVAL
#define PW_ACCT_INTERIM_INTERVAL 85
#endif
#endif

#if RADCLI_VERSION_NUMBER < 0x010207
#define CHALLENGE_RC 3
#endif

#define MAX_CHALLENGES 16
#define MAX_RADIUS_ASYNC_ROUTES 4096
#define MAX_RADIUS_ASYNC_STRING 4096
#define MAX_RADIUS_ASYNC_STATE 4096

/* Per-blob read timeout for the helper socketpair. The full RADIUS
 * round-trip happens inside the helper, then the result is written
 * to the socket in one burst, so the only waits the parent should
 * see here are scheduler hiccups. */
#define RADIUS_HELPER_READ_TIMEOUT 5

static void radius_vhost_init(void **_vctx, void *pool, void *additional)
{
	radius_cfg_st *config = additional;
	struct radius_vhost_ctx *vctx;

	if (config == NULL)
		goto fail;

	vctx = talloc_zero(pool, struct radius_vhost_ctx);
	if (vctx == NULL)
		goto fail;

	if (config->config)
		strlcpy(vctx->config, config->config, sizeof(vctx->config));

	vctx->rh = rc_read_config(config->config);
	if (vctx->rh == NULL) {
		goto fail;
	}

	if (config->nas_identifier) {
		strlcpy(vctx->nas_identifier, config->nas_identifier,
			sizeof(vctx->nas_identifier));
	} else {
		vctx->nas_identifier[0] = 0;
	}

	if (config->group_separator) {
		strlcpy(vctx->group_separator, config->group_separator,
			sizeof(vctx->group_separator));
	} else {
		strlcpy(vctx->group_separator, ";",
			sizeof(vctx->group_separator));
	}

	if (rc_read_dictionary(vctx->rh, rc_conf_str(vctx->rh, "dictionary")) !=
	    0) {
		fprintf(stderr, "error reading the radius dictionary\n");
		exit(EXIT_FAILURE);
	}
	*_vctx = vctx;

	return;
fail:
	fprintf(stderr, "radius initialization error\n");
	exit(EXIT_FAILURE);
}

static void radius_vhost_deinit(void *_vctx)
{
	struct radius_vhost_ctx *vctx = _vctx;

	if (vctx->rh != NULL)
		rc_destroy(vctx->rh);
}

static int radius_auth_init(void **ctx, void *pool, void *_vctx,
			    const common_auth_init_st *info)
{
	struct radius_ctx_st *pctx;
	char *default_realm;
	struct radius_vhost_ctx *vctx = _vctx;

	if (info->username == NULL || info->username[0] == 0) {
		oc_syslog(LOG_NOTICE, "radius-auth: no username present");
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct radius_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	if (info->ip)
		strlcpy(pctx->remote_ip, info->ip, sizeof(pctx->remote_ip));
	if (info->our_ip)
		strlcpy(pctx->our_ip, info->our_ip, sizeof(pctx->our_ip));

	pctx->pass_msg[0] = 0;
	pctx->vctx = vctx;
	pctx->passwd_counter = 0;

	default_realm = rc_conf_str(pctx->vctx->rh, "default_realm");

	if ((strchr(info->username, '@') == NULL) && default_realm &&
	    default_realm[0] != 0) {
		snprintf(pctx->username, sizeof(pctx->username), "%s@%s",
			 info->username, default_realm);
	} else {
		strlcpy(pctx->username, info->username, sizeof(pctx->username));
	}
	pctx->id = info->id;

	if (info->user_agent)
		strlcpy(pctx->user_agent, info->user_agent,
			sizeof(pctx->user_agent));

	*ctx = pctx;

	return ERR_AUTH_CONTINUE;
}

static int radius_auth_group(void *ctx, const char *suggested, char *groupname,
			     int groupname_size)
{
	struct radius_ctx_st *pctx = ctx;
	unsigned int i;

	groupname[0] = 0;

	if (suggested != NULL) {
		for (i = 0; i < pctx->groupnames_size; i++) {
			if (strcmp(suggested, pctx->groupnames[i]) == 0) {
				strlcpy(groupname, pctx->groupnames[i],
					groupname_size);
				return 0;
			}
		}

		oc_syslog(
			LOG_NOTICE,
			"radius-auth: user '%s' requested group '%s' but is not a member",
			pctx->username, suggested);
		return -1;
	}

	if (pctx->groupnames_size > 0 && groupname[0] == 0) {
		strlcpy(groupname, pctx->groupnames[0], groupname_size);
	}

	return 0;
}

static int radius_auth_user(void *ctx, char *username, int username_size)
{
	/* do not update username */
	return -1;
}

static void append_route(struct radius_ctx_st *pctx, const char *route,
			 unsigned int len)
{
	unsigned int i;
	const char *p;

	/* accept route/mask */
	p = strchr(route, '/');
	if (p == 0)
		return;

	p = strchr(p, ' ');
	if (p != NULL) {
		len = p - route;
	}

	if (pctx->routes_size == 0) {
		pctx->routes = talloc_size(pctx, sizeof(char *));
	} else {
		pctx->routes = talloc_realloc_size(pctx, pctx->routes,
						   (pctx->routes_size + 1) *
							   sizeof(char *));
	}

	if (pctx->routes != NULL) {
		i = pctx->routes_size;
		pctx->routes[i] = talloc_strndup(pctx, route, len);
		if (pctx->routes[i] != NULL)
			pctx->routes_size++;
	}
}

static int set_radius_state(struct radius_ctx_st *pctx, const VALUE_PAIR *vp)
{
	talloc_free(pctx->state);
	pctx->state = NULL;
	pctx->state_len = 0;

	if (vp->lvalue == 0)
		return 0;

	pctx->state = talloc_memdup(pctx, vp->strvalue, vp->lvalue);
	if (pctx->state == NULL)
		return -1;

	pctx->state_len = vp->lvalue;
	return 0;
}

/* Parses group of format "OU=group1<sep>group2<sep>group3" */
static void parse_groupnames(struct radius_ctx_st *pctx, const char *full,
			     unsigned int len)
{
	char *p, *p2;
	const char *sep = pctx->vctx->group_separator;
	char *orig;

	p = talloc_strndup(pctx, full, len);
	if (p == NULL)
		return;
	full = p;

	if (pctx->groupnames_size >= MAX_GROUPS) {
		oc_syslog(
			LOG_WARNING,
			"radius-auth: cannot handle more than %d groups, ignoring group string %s",
			MAX_GROUPS, full);
	} else if (len >= 3 && memcmp(full, "OU=", 3) == 0) {
		oc_syslog(LOG_DEBUG, "radius-auth: found group string %s",
			  full);
		full += 3;

		p = talloc_strdup(pctx, full);
		if (p == NULL)
			return;
		orig = p;

		p2 = strsep(&p, sep);
		while (p2 != NULL) {
			char *gname = talloc_strdup(pctx, p2);

			if (gname == NULL)
				break;
			pctx->groupnames[pctx->groupnames_size++] = gname;

			oc_syslog(LOG_DEBUG, "radius-auth: found group %s",
				  gname);

			p2 = strsep(&p, sep);

			if (pctx->groupnames_size == MAX_GROUPS) {
				if (p2)
					oc_syslog(
						LOG_WARNING,
						"radius-auth: cannot handle more than %d groups, ignoring trailing group(s) %s",
						MAX_GROUPS, p2);
				break;
			}
		}
		talloc_free(orig);
	} else {
		oc_syslog(LOG_DEBUG, "radius-auth: found group string %s",
			  full);
		pctx->groupnames[pctx->groupnames_size++] = p;
	}
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int radius_auth_pass(void *ctx, const char *pass, unsigned int pass_len)
{
	struct radius_ctx_st *pctx = ctx;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	uint32_t service;
	char route[72];
	char txt[64];
	VALUE_PAIR *vp;
	int ret;

	/* send Access-Request */
	oc_syslog(LOG_DEBUG,
		  "radius-auth: communicating username (%s) and password",
		  pctx->username);
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_USER_NAME, pctx->username,
			  -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		return ERR_AUTH_FAIL;
	}

	if (rc_avpair_add(pctx->vctx->rh, &send, PW_USER_PASSWORD, (char *)pass,
			  -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->our_ip[0] != 0) {
		struct in_addr in;
		struct in6_addr in6;

		if (inet_pton(AF_INET, pctx->our_ip, &in) != 0) {
			in.s_addr = ntohl(in.s_addr);
			if (rc_avpair_add(pctx->vctx->rh, &send,
					  PW_NAS_IP_ADDRESS, (char *)&in,
					  sizeof(struct in_addr), 0) == NULL) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: error in constructing radius message for user '%s'",
					__func__, __LINE__, pctx->username);
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
		} else if (inet_pton(AF_INET6, pctx->our_ip, &in6) != 0) {
			if (rc_avpair_add(pctx->vctx->rh, &send,
					  PW_NAS_IPV6_ADDRESS, (char *)&in6,
					  sizeof(struct in6_addr), 0) == NULL) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: error in constructing radius message for user '%s'",
					__func__, __LINE__, pctx->username);
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
		}
	}

	if (pctx->vctx->nas_identifier[0] != 0) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_NAS_IDENTIFIER,
				  pctx->vctx->nas_identifier, -1, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	if (rc_avpair_add(pctx->vctx->rh, &send, PW_CALLING_STATION_ID,
			  pctx->remote_ip, -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->user_agent[0] != 0) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_CONNECT_INFO,
				  pctx->user_agent, -1, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_SERVICE_TYPE, &service, -1,
			  0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	service = PW_ASYNC;
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_NAS_PORT_TYPE, &service, -1,
			  0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->state != NULL) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_STATE, pctx->state,
				  pctx->state_len, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		talloc_free(pctx->state);
		pctx->state = NULL;
		pctx->state_len = 0;
	}

	pctx->pass_msg[0] = 0;
	ret = rc_aaa(pctx->vctx->rh, 0, send, &recvd, pctx->pass_msg, 0,
		     PW_ACCESS_REQUEST);

	if (ret == OK_RC) {
		uint32_t ipv4;
		uint8_t ipv6[16];

		vp = recvd;

		while (vp != NULL) {
			if (vp->attribute == PW_SERVICE_TYPE &&
			    vp->lvalue != PW_FRAMED) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: unknown radius service type '%d'",
					__func__, __LINE__, (int)vp->lvalue);
				goto fail;
			} else if (vp->attribute == RAD_GROUP_NAME &&
				   vp->type == PW_TYPE_STRING) {
				/* Group-Name */
				parse_groupnames(pctx, vp->strvalue,
						 vp->lvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ADDRESS &&
				   vp->type == PW_TYPE_IPV6ADDR) {
				/* Framed-IPv6-Address */
				if (inet_ntop(AF_INET6, vp->strvalue,
					      pctx->ipv6,
					      sizeof(pctx->ipv6)) != NULL) {
					pctx->ipv6_subnet_prefix = 64;
					strlcpy(pctx->ipv6_net, pctx->ipv6,
						sizeof(pctx->ipv6_net));
				}
			} else if (vp->attribute == PW_DELEGATED_IPV6_PREFIX &&
				   vp->type == PW_TYPE_IPV6PREFIX) {
				/* Delegated-IPv6-Prefix */
				if (inet_ntop(AF_INET6, vp->strvalue,
					      pctx->ipv6,
					      sizeof(pctx->ipv6)) != NULL) {
					memset(ipv6, 0, sizeof(ipv6));
					memcpy(ipv6, vp->strvalue + 2,
					       vp->lvalue - 2);
					if (inet_ntop(AF_INET6, ipv6,
						      pctx->ipv6,
						      sizeof(pctx->ipv6)) !=
					    NULL) {
						pctx->ipv6_subnet_prefix =
							(unsigned int)(unsigned char)
								vp->strvalue[1];
					}
				}
			} else if (vp->attribute == PW_FRAMED_IPV6_PREFIX &&
				   vp->type == PW_TYPE_IPV6PREFIX) {
				if (vp->lvalue > 2 && vp->lvalue <= 18) {
					/* Framed-IPv6-Prefix */
					memset(ipv6, 0, sizeof(ipv6));
					memcpy(ipv6, vp->strvalue + 2,
					       vp->lvalue - 2);
					if (inet_ntop(AF_INET6, ipv6, txt,
						      sizeof(txt)) != NULL) {
						snprintf(
							route, sizeof(route),
							"%s/%u", txt,
							(unsigned int)(unsigned char)
								vp->strvalue[1]);
						append_route(pctx, route,
							     strlen(route));
					}
				}
			} else if (vp->attribute ==
					   PW_DNS_SERVER_IPV6_ADDRESS &&
				   vp->type == PW_TYPE_IPV6ADDR) {
				/* DNS-Server-IPv6-Address */
				if (pctx->ipv6_dns1[0] == 0)
					inet_ntop(AF_INET6, vp->strvalue,
						  pctx->ipv6_dns1,
						  sizeof(pctx->ipv6_dns1));
				else if (pctx->ipv6_dns2[0] == 0)
					inet_ntop(AF_INET6, vp->strvalue,
						  pctx->ipv6_dns2,
						  sizeof(pctx->ipv6_dns2));
				else {
					char dst[MAX_IP_STR];

					inet_ntop(AF_INET6, vp->strvalue, dst,
						  sizeof(dst));
					oc_syslog(
						LOG_NOTICE,
						"radius-auth: cannot handle more than 2 DNS servers, ignoring additional DNS server from RADIUS: %s",
						dst);
				}
			} else if (vp->attribute == PW_FRAMED_IP_ADDRESS &&
				   vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Address */
				if (vp->lvalue != 0xffffffff &&
				    vp->lvalue != 0xfffffffe) {
					/* According to RFC2865 the values above (fe) instruct the
					 * server to assign an address from the pool of the server,
					 * and (ff) to assign address as negotiated with the client.
					 * We don't negotiate with clients.
					 */
					ipv4 = htonl(vp->lvalue);
					inet_ntop(AF_INET, &ipv4, pctx->ipv4,
						  sizeof(pctx->ipv4));
				}
			} else if (vp->attribute == PW_FRAMED_IP_NETMASK &&
				   vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Netmask */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_mask,
					  sizeof(pctx->ipv4_mask));
			} else if (vp->attribute == MS_PRIMARY_DNS_SERVER &&
				   vp->type == PW_TYPE_IPADDR) {
				/* MS-Primary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns1,
					  sizeof(pctx->ipv4_dns1));
			} else if (vp->attribute == MS_SECONDARY_DNS_SERVER &&
				   vp->type == PW_TYPE_IPADDR) {
				/* MS-Secondary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns2,
					  sizeof(pctx->ipv4_dns2));
			} else if (vp->attribute == PW_FRAMED_ROUTE &&
				   vp->type == PW_TYPE_STRING) {
				/* Framed-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ROUTE &&
				   vp->type == PW_TYPE_STRING) {
				/* Framed-IPv6-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else if (vp->attribute == PW_ACCT_INTERIM_INTERVAL &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->interim_interval_secs = vp->lvalue;
			} else if (vp->attribute == PW_SESSION_TIMEOUT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->session_timeout_secs = vp->lvalue;
			} else if (vp->attribute == RP_UPSTREAM_SPEED_LIMIT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->rx_per_sec = vp->lvalue;
			} else if (vp->attribute == RP_DOWNSTREAM_SPEED_LIMIT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->tx_per_sec = vp->lvalue;
			} else {
				oc_syslog(
					LOG_DEBUG,
					"radius-auth: ignoring server's attribute (%u,%u) of type %u",
#ifndef ATTRID /* FreeRADIUS client >= 1.1.8 */
					(unsigned int)vp->attribute,
#else
					(unsigned int)ATTRID(vp->attribute),
#endif
#ifndef VENDOR /* FreeRADIUS client >= 1.1.8 */
					(unsigned int)vp->vendor,
#else
					(unsigned int)VENDOR(vp->attribute),
#endif
					(unsigned int)vp->type);
			}
			vp = vp->next;
		}

		ret = 0;
		goto cleanup;
	} else if (ret == CHALLENGE_RC) {
		vp = recvd;

		while (vp != NULL) {
			if (vp->attribute == PW_STATE &&
			    vp->type == PW_TYPE_STRING) {
				/* State */
				if (set_radius_state(pctx, vp) < 0)
					goto fail;

				pctx->id++;
				oc_syslog(
					LOG_DEBUG,
					"radius-auth: Access-Challenge response stage %u, State length %u",
					pctx->passwd_counter, vp->lvalue);
				ret = ERR_AUTH_CONTINUE;
			}
			vp = vp->next;
		}

		/* PW_STATE or PW_REPLY_MESSAGE is empty or MAX_CHALLENGES limit exceeded */
		if ((pctx->pass_msg[0] == 0) || (pctx->state == NULL) ||
		    (pctx->passwd_counter >= MAX_CHALLENGES)) {
			strlcpy(pctx->pass_msg, pass_msg_failed,
				sizeof(pctx->pass_msg));
			oc_syslog(
				LOG_ERR,
				"radius-auth: Access-Challenge with invalid State or Reply-Message, or max number of password requests exceeded");
			ret = ERR_AUTH_FAIL;
		}
		goto cleanup;
	} else {
fail:
		if (pctx->pass_msg[0] == 0)
			strlcpy(pctx->pass_msg, pass_msg_failed,
				sizeof(pctx->pass_msg));

		if (pctx->retries++ < MAX_PASSWORD_TRIES - 1 &&
		    pctx->passwd_counter == 0) {
			ret = ERR_AUTH_CONTINUE;
			goto cleanup;
		}

		oc_syslog(
			LOG_NOTICE,
			"radius-auth: error authenticating user '%s' (code %d)",
			pctx->username, ret);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

cleanup:
	if (send != NULL)
		rc_avpair_free(send);
	if (recvd != NULL)
		rc_avpair_free(recvd);
	return ret;
}

struct radius_async_result_hdr {
	int32_t auth_ret;
	uint32_t groupnames_size;
	uint32_t routes_size;
	uint32_t state_len;
	uint32_t interim_interval_secs;
	uint32_t session_timeout_secs;
	uint32_t rx_per_sec;
	uint32_t tx_per_sec;
	uint32_t retries;
	uint32_t id;
	uint32_t passwd_counter;
	uint64_t prev_prompt_hash;
	uint16_t ipv6_subnet_prefix;
	char pass_msg[PW_MAX_MSG_SIZE];
	char ipv4[MAX_IP_STR];
	char ipv4_mask[MAX_IP_STR];
	char ipv4_dns1[MAX_IP_STR];
	char ipv4_dns2[MAX_IP_STR];
	char ipv6[MAX_IP_STR];
	char ipv6_net[MAX_IP_STR];
	char ipv6_dns1[MAX_IP_STR];
	char ipv6_dns2[MAX_IP_STR];
};

struct radius_async_request_hdr {
	uint32_t state_len;
	uint32_t retries;
	uint32_t id;
	uint32_t passwd_counter;
	uint64_t prev_prompt_hash;
};

static int write_blob(int fd, const void *data, size_t len)
{
	if (data == NULL && len > 0)
		return -1;
	if (len == 0)
		return 0;
	return force_write(fd, data, len) == (ssize_t)len ? 0 : -1;
}

static int read_blob(int fd, void *data, size_t len)
{
	if (data == NULL && len > 0)
		return -1;
	if (len == 0)
		return 0;
	return force_read_timeout(fd, data, len, RADIUS_HELPER_READ_TIMEOUT) ==
			       (ssize_t)len ?
		       0 :
		       -1;
}

static int write_counted_data(int fd, const void *data, size_t len)
{
	uint32_t wire_len;

	if (data == NULL && len > 0)
		return -1;
	if (len > UINT32_MAX)
		return -1;

	wire_len = (uint32_t)len;

	if (write_blob(fd, &wire_len, sizeof(wire_len)) < 0)
		return -1;
	return write_blob(fd, data, len);
}

static int write_counted_string(int fd, const char *str)
{
	return write_counted_data(fd, str, str ? strlen(str) : 0);
}

static char *read_counted_string(void *pool, int fd, uint32_t max_len)
{
	uint32_t len;
	char *str;

	if (read_blob(fd, &len, sizeof(len)) < 0)
		return NULL;
	if (len > max_len)
		return NULL;
	if (len == 0)
		return talloc_strdup(pool, "");

	str = talloc_size(pool, (size_t)len + 1);
	if (str == NULL)
		return NULL;
	if (read_blob(fd, str, len) < 0) {
		talloc_free(str);
		return NULL;
	}
	str[len] = 0;
	return str;
}

static int radius_auth_pass_write_result(int fd, struct radius_ctx_st *pctx,
					 int auth_ret)
{
	struct radius_async_result_hdr hdr;
	unsigned int i;

	memset(&hdr, 0, sizeof(hdr));

	if (pctx->groupnames_size > MAX_GROUPS ||
	    pctx->routes_size > MAX_RADIUS_ASYNC_ROUTES ||
	    pctx->state_len > MAX_RADIUS_ASYNC_STATE)
		return -1;

	hdr.auth_ret = auth_ret;
	hdr.groupnames_size = pctx->groupnames_size;
	hdr.routes_size = pctx->routes_size;
	hdr.state_len = (uint32_t)pctx->state_len;
	hdr.interim_interval_secs = pctx->interim_interval_secs;
	hdr.session_timeout_secs = pctx->session_timeout_secs;
	hdr.rx_per_sec = pctx->rx_per_sec;
	hdr.tx_per_sec = pctx->tx_per_sec;
	hdr.retries = pctx->retries;
	hdr.id = pctx->id;
	hdr.passwd_counter = pctx->passwd_counter;
	hdr.prev_prompt_hash = pctx->prev_prompt_hash;
	hdr.ipv6_subnet_prefix = pctx->ipv6_subnet_prefix;
	strlcpy(hdr.pass_msg, pctx->pass_msg, sizeof(hdr.pass_msg));
	strlcpy(hdr.ipv4, pctx->ipv4, sizeof(hdr.ipv4));
	strlcpy(hdr.ipv4_mask, pctx->ipv4_mask, sizeof(hdr.ipv4_mask));
	strlcpy(hdr.ipv4_dns1, pctx->ipv4_dns1, sizeof(hdr.ipv4_dns1));
	strlcpy(hdr.ipv4_dns2, pctx->ipv4_dns2, sizeof(hdr.ipv4_dns2));
	strlcpy(hdr.ipv6, pctx->ipv6, sizeof(hdr.ipv6));
	strlcpy(hdr.ipv6_net, pctx->ipv6_net, sizeof(hdr.ipv6_net));
	strlcpy(hdr.ipv6_dns1, pctx->ipv6_dns1, sizeof(hdr.ipv6_dns1));
	strlcpy(hdr.ipv6_dns2, pctx->ipv6_dns2, sizeof(hdr.ipv6_dns2));

	if (write_blob(fd, &hdr, sizeof(hdr)) < 0)
		return -1;
	if (write_blob(fd, pctx->state, pctx->state_len) < 0)
		return -1;

	for (i = 0; i < pctx->groupnames_size; i++) {
		if (pctx->groupnames[i] != NULL &&
		    strlen(pctx->groupnames[i]) > MAX_GROUPNAME_SIZE)
			return -1;
		if (write_counted_string(fd, pctx->groupnames[i]) < 0)
			return -1;
	}

	for (i = 0; i < pctx->routes_size; i++) {
		if (pctx->routes[i] != NULL &&
		    strlen(pctx->routes[i]) > MAX_RADIUS_ASYNC_STRING)
			return -1;
		if (write_counted_string(fd, pctx->routes[i]) < 0)
			return -1;
	}

	return 0;
}

static void radius_ctx_clear_dynamic(struct radius_ctx_st *pctx)
{
	unsigned int i;

	for (i = 0; i < pctx->groupnames_size; i++) {
		talloc_free(pctx->groupnames[i]);
		pctx->groupnames[i] = NULL;
	}
	pctx->groupnames_size = 0;

	for (i = 0; i < pctx->routes_size; i++)
		talloc_free(pctx->routes[i]);
	talloc_free(pctx->routes);
	pctx->routes = NULL;
	pctx->routes_size = 0;

	talloc_free(pctx->state);
	pctx->state = NULL;
	pctx->state_len = 0;
}

int radius_auth_is_async_candidate(const struct auth_mod_st *module)
{
	return module == &radius_auth_funcs;
}

int radius_auth_pass_async_send_request(void *ctx, const char *pass,
					unsigned int pass_len, int fd)
{
	struct radius_ctx_st *pctx = ctx;
	struct radius_async_request_hdr hdr;

	if (pctx->state_len > MAX_RADIUS_ASYNC_STATE ||
	    pass_len > MAX_RADIUS_ASYNC_STRING)
		return -1;

	memset(&hdr, 0, sizeof(hdr));
	hdr.state_len = (uint32_t)pctx->state_len;
	hdr.retries = pctx->retries;
	hdr.id = pctx->id;
	hdr.passwd_counter = pctx->passwd_counter;
	hdr.prev_prompt_hash = pctx->prev_prompt_hash;

	if (write_blob(fd, &hdr, sizeof(hdr)) < 0)
		return -1;
	if (write_counted_string(fd, pctx->vctx->config) < 0)
		return -1;
	if (write_counted_string(fd, pctx->vctx->nas_identifier) < 0)
		return -1;
	if (write_counted_string(fd, pctx->vctx->group_separator) < 0)
		return -1;
	if (write_counted_string(fd, pctx->username) < 0)
		return -1;
	if (write_counted_string(fd, pctx->remote_ip) < 0)
		return -1;
	if (write_counted_string(fd, pctx->our_ip) < 0)
		return -1;
	if (write_counted_string(fd, pctx->user_agent) < 0)
		return -1;
	if (write_counted_data(fd, pass, pass != NULL ? pass_len : 0) < 0)
		return -1;
	if (write_blob(fd, pctx->state, pctx->state_len) < 0)
		return -1;

	return 0;
}

int radius_auth_helper_main(int fd)
{
	void *pool;
	struct radius_vhost_ctx *vctx;
	struct radius_ctx_st *pctx;
	struct radius_async_request_hdr hdr;
	char *config;
	char *nas_identifier;
	char *group_separator;
	char *password;
	int ret;

	pool = talloc_init("radius-auth-helper");
	if (pool == NULL)
		return EXIT_FAILURE;

	vctx = talloc_zero(pool, struct radius_vhost_ctx);
	pctx = talloc_zero(pool, struct radius_ctx_st);
	if (vctx == NULL || pctx == NULL)
		return EXIT_FAILURE;

	if (read_blob(fd, &hdr, sizeof(hdr)) < 0)
		return EXIT_FAILURE;
	if (hdr.state_len > MAX_RADIUS_ASYNC_STATE)
		return EXIT_FAILURE;

	config = read_counted_string(pool, fd, _POSIX_PATH_MAX - 1);
	nas_identifier =
		read_counted_string(pool, fd, sizeof(vctx->nas_identifier) - 1);
	group_separator = read_counted_string(
		pool, fd, sizeof(vctx->group_separator) - 1);
	if (config == NULL || nas_identifier == NULL || group_separator == NULL)
		return EXIT_FAILURE;

	strlcpy(vctx->config, config, sizeof(vctx->config));
	strlcpy(vctx->nas_identifier, nas_identifier,
		sizeof(vctx->nas_identifier));
	if (group_separator[0] != 0)
		strlcpy(vctx->group_separator, group_separator,
			sizeof(vctx->group_separator));
	else
		strlcpy(vctx->group_separator, ";",
			sizeof(vctx->group_separator));

	pctx->vctx = vctx;
	if ((pctx->vctx->rh = rc_read_config(vctx->config)) == NULL)
		return EXIT_FAILURE;
	if (rc_read_dictionary(pctx->vctx->rh,
			       rc_conf_str(pctx->vctx->rh, "dictionary")) != 0)
		return EXIT_FAILURE;

	config = read_counted_string(pool, fd, sizeof(pctx->username) - 1);
	if (config == NULL)
		return EXIT_FAILURE;
	strlcpy(pctx->username, config, sizeof(pctx->username));

	config = read_counted_string(pool, fd, sizeof(pctx->remote_ip) - 1);
	if (config == NULL)
		return EXIT_FAILURE;
	strlcpy(pctx->remote_ip, config, sizeof(pctx->remote_ip));

	config = read_counted_string(pool, fd, sizeof(pctx->our_ip) - 1);
	if (config == NULL)
		return EXIT_FAILURE;
	strlcpy(pctx->our_ip, config, sizeof(pctx->our_ip));

	config = read_counted_string(pool, fd, sizeof(pctx->user_agent) - 1);
	if (config == NULL)
		return EXIT_FAILURE;
	strlcpy(pctx->user_agent, config, sizeof(pctx->user_agent));

	password = read_counted_string(pool, fd, MAX_RADIUS_ASYNC_STRING);
	if (password == NULL)
		return EXIT_FAILURE;

	pctx->retries = hdr.retries;
	pctx->id = hdr.id;
	pctx->passwd_counter = hdr.passwd_counter;
	pctx->prev_prompt_hash = hdr.prev_prompt_hash;

	if (hdr.state_len > 0) {
		pctx->state = talloc_size(pctx, hdr.state_len);
		if (pctx->state == NULL)
			return EXIT_FAILURE;
		if (read_blob(fd, pctx->state, hdr.state_len) < 0)
			return EXIT_FAILURE;
		pctx->state_len = hdr.state_len;
	}

	ret = radius_auth_pass(pctx, password, (unsigned int)strlen(password));
	if (radius_auth_pass_write_result(fd, pctx, ret) < 0)
		return EXIT_FAILURE;

	talloc_free(pool);
	return EXIT_SUCCESS;
}

int radius_auth_pass_async_apply(void *ctx, int fd, int *auth_ret)
{
	struct radius_ctx_st *pctx = ctx;
	struct radius_async_result_hdr hdr;
	unsigned int i;

	if (read_blob(fd, &hdr, sizeof(hdr)) < 0)
		return -1;

	if (hdr.state_len > MAX_RADIUS_ASYNC_STATE ||
	    hdr.groupnames_size > MAX_GROUPS ||
	    hdr.routes_size > MAX_RADIUS_ASYNC_ROUTES)
		return -1;

	radius_ctx_clear_dynamic(pctx);

	pctx->interim_interval_secs = hdr.interim_interval_secs;
	pctx->session_timeout_secs = hdr.session_timeout_secs;
	pctx->rx_per_sec = hdr.rx_per_sec;
	pctx->tx_per_sec = hdr.tx_per_sec;
	pctx->retries = hdr.retries;
	pctx->id = hdr.id;
	pctx->passwd_counter = hdr.passwd_counter;
	pctx->prev_prompt_hash = hdr.prev_prompt_hash;
	pctx->ipv6_subnet_prefix = hdr.ipv6_subnet_prefix;
	strlcpy(pctx->pass_msg, hdr.pass_msg, sizeof(pctx->pass_msg));
	strlcpy(pctx->ipv4, hdr.ipv4, sizeof(pctx->ipv4));
	strlcpy(pctx->ipv4_mask, hdr.ipv4_mask, sizeof(pctx->ipv4_mask));
	strlcpy(pctx->ipv4_dns1, hdr.ipv4_dns1, sizeof(pctx->ipv4_dns1));
	strlcpy(pctx->ipv4_dns2, hdr.ipv4_dns2, sizeof(pctx->ipv4_dns2));
	strlcpy(pctx->ipv6, hdr.ipv6, sizeof(pctx->ipv6));
	strlcpy(pctx->ipv6_net, hdr.ipv6_net, sizeof(pctx->ipv6_net));
	strlcpy(pctx->ipv6_dns1, hdr.ipv6_dns1, sizeof(pctx->ipv6_dns1));
	strlcpy(pctx->ipv6_dns2, hdr.ipv6_dns2, sizeof(pctx->ipv6_dns2));

	if (hdr.state_len > 0) {
		pctx->state = talloc_size(pctx, hdr.state_len);
		if (pctx->state == NULL)
			return -1;
		if (read_blob(fd, pctx->state, hdr.state_len) < 0)
			return -1;
		pctx->state_len = hdr.state_len;
	}

	for (i = 0; i < hdr.groupnames_size; i++) {
		pctx->groupnames[i] =
			read_counted_string(pctx, fd, MAX_GROUPNAME_SIZE);
		if (pctx->groupnames[i] == NULL)
			return -1;
		pctx->groupnames_size++;
	}

	if (hdr.routes_size > 0) {
		pctx->routes = talloc_zero_size(pctx, sizeof(char *) *
							      hdr.routes_size);
		if (pctx->routes == NULL)
			return -1;
	}

	for (i = 0; i < hdr.routes_size; i++) {
		pctx->routes[i] =
			read_counted_string(pctx, fd, MAX_RADIUS_ASYNC_STRING);
		if (pctx->routes[i] == NULL)
			return -1;
		pctx->routes_size++;
	}

	*auth_ret = hdr.auth_ret;
	return 0;
}

static int radius_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	struct radius_ctx_st *pctx = ctx;
	size_t prompt_hash = 0;

	if (pctx->pass_msg[0] != 0)
		pst->msg_str = talloc_strdup(pool, pctx->pass_msg);

	if (pctx->state != NULL) {
		/* differentiate password prompts, if the hash of the prompt
		 * is different.
		 */
		prompt_hash =
			hash_any(pctx->pass_msg, strlen(pctx->pass_msg), 0);
		if (pctx->prev_prompt_hash != (uint64_t)prompt_hash)
			pctx->passwd_counter++;
		pctx->prev_prompt_hash = (uint64_t)prompt_hash;
		pst->counter = pctx->passwd_counter;
	}

	/* use default prompt */
	return 0;
}

static void radius_auth_deinit(void *ctx)
{
	struct radius_ctx_st *pctx = ctx;

	talloc_free(pctx);
}

const struct auth_mod_st radius_auth_funcs = {
	.type = AUTH_TYPE_RADIUS | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.vhost_init = radius_vhost_init,
	.vhost_deinit = radius_vhost_deinit,
	.auth_init = radius_auth_init,
	.auth_deinit = radius_auth_deinit,
	.auth_msg = radius_auth_msg,
	.auth_pass = radius_auth_pass,
	.auth_user = radius_auth_user,
	.auth_group = radius_auth_group,
	.group_list = NULL
};

#endif
