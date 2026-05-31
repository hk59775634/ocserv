/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015 Red Hat
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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <ctype.h>

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

#define HTML_404 "<html><body><h1>404 Not Found</h1></body></html>\r\n"
#define HTML_401 "<html><body><h1>401 Unauthorized</h1></body></html>\r\n"

int response_404(worker_st *ws, unsigned int http_ver)
{
	if (cstp_printf(ws, "HTTP/1.%u 404 Not found\r\n", http_ver) < 0 ||
	    cstp_printf(ws, "Content-Length: %u\r\n",
			(unsigned int)(sizeof(HTML_404) - 1)) < 0 ||
	    cstp_puts(ws, "Connection: close\r\n\r\n") < 0 ||
	    cstp_puts(ws, HTML_404) < 0)
		return -1;
	return 0;
}

int response_401(worker_st *ws, unsigned int http_ver, char *realm)
{
	if (cstp_printf(ws, "HTTP/1.%u 401 Unauthorized\r\n", http_ver) < 0 ||
	    cstp_printf(ws, "WWW-Authenticate: Basic realm=\"%s\"\r\n", realm) <
		    0 ||
	    cstp_printf(ws, "Content-Length: %u\r\n",
			(unsigned int)(sizeof(HTML_401) - 1)) < 0 ||
	    cstp_puts(ws, "Connection: close\r\n\r\n") < 0 ||
	    cstp_puts(ws, HTML_401) < 0)
		return -1;
	return 0;
}

static int send_headers(worker_st *ws, unsigned int http_ver,
			const char *content_type, unsigned int content_length)
{
	if (cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver) < 0 ||
	    cstp_puts(ws, "Connection: Keep-Alive\r\n") < 0 ||
	    cstp_printf(ws, "Content-Type: %s\r\n", content_type) < 0 ||
	    cstp_puts(ws, "X-Transcend-Version: 1\r\n") < 0 ||
	    cstp_printf(ws, "Content-Length: %u\r\n", content_length) < 0 ||
	    add_owasp_headers(ws) < 0 || cstp_puts(ws, "\r\n") < 0)
		return -1;
	return 0;
}

static int send_data(worker_st *ws, unsigned int http_ver,
		     const char *content_type, const char *data,
		     int content_length)
{
	/* don't bother uncorking on error - the connection will be closed anyway */
	cstp_cork(ws);
	if (send_headers(ws, http_ver, content_type, content_length) < 0 ||
	    cstp_send(ws, data, content_length) < 0 || cstp_uncork(ws) < 0)
		return -1;
	return 0;
}

#ifdef ANYCONNECT_CLIENT_COMPAT
int get_config_handler(worker_st *ws, unsigned int http_ver)
{
	int ret;
	struct stat st;

	oclog(ws, LOG_HTTP_DEBUG, "requested config: %s", ws->req.url);

	cookie_authenticate_or_exit(ws);

	if (ws->user_config->xml_config_file == NULL) {
		oclog(ws, LOG_INFO,
		      "requested config but no config file is set");
		response_404(ws, http_ver);
		return -1;
	}

	ret = stat(ws->user_config->xml_config_file, &st);
	if (ret == -1) {
		oclog(ws, LOG_INFO, "cannot load config file '%s'",
		      ws->user_config->xml_config_file);
		response_404(ws, http_ver);
		return -1;
	}

	cstp_cork(ws);
	if (send_headers(ws, http_ver, "text/xml", (unsigned int)st.st_size) <
		    0 ||
	    cstp_uncork(ws) < 0)
		return -1;

	ret = cstp_send_file(ws, ws->user_config->xml_config_file);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s",
		      ws->user_config->xml_config_file, gnutls_strerror(ret));
		return -1;
	}

	return 0;
}

#define VPN_VERSION "0,0,0000\n"
#define XML_START \
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"

#define AC_BINARIES_DIR "1/binaries"
#define AC_BINARIES_URL "/1/binaries/"

struct ac_platform_st {
	const char *name;
	const char *version;
	const char *filename;
};

struct ac_update_st {
	struct ac_platform_st windows;
	struct ac_platform_st windows_arm64;
	struct ac_platform_st macos;
	struct ac_platform_st linux;
	struct ac_platform_st linux64;
};

static bool valid_webdeploy_filename(const char *name)
{
	const char *p;

	for (p = name; *p != 0; p++) {
		if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' ||
		      *p == '-'))
			return false;
	}

	return strstr(name, "webdeploy") != NULL ||
	       strstr(name, "web-deploy") != NULL;
}

static const char *filename_ext(const char *name)
{
	const char *p = strrchr(name, '.');

	if (p == NULL || p[1] == 0)
		return "pkg";

	if (strcmp(p + 1, "sh") == 0)
		return "script";

	return p + 1;
}

static const char *match_prefix(const char *name, struct ac_update_st *updates,
				struct ac_platform_st **platform)
{
	enum ac_platform_id {
		AC_PLATFORM_WINDOWS,
		AC_PLATFORM_WINDOWS_ARM64,
		AC_PLATFORM_MACOS,
		AC_PLATFORM_LINUX,
		AC_PLATFORM_LINUX64,
	};
	static const struct {
		const char *prefix;
		enum ac_platform_id platform;
	} prefixes[] = {
		{ "anyconnect-win-arm64-", AC_PLATFORM_WINDOWS_ARM64 },
		{ "anyconnect-win-", AC_PLATFORM_WINDOWS },
		{ "anyconnect-win64-", AC_PLATFORM_WINDOWS },
		{ "anyconnect-macos-", AC_PLATFORM_MACOS },
		{ "anyconnect-linux64-", AC_PLATFORM_LINUX64 },
		{ "anyconnect-linux-", AC_PLATFORM_LINUX },
		{ "cisco-secure-client-win-arm64-", AC_PLATFORM_WINDOWS_ARM64 },
		{ "cisco-secure-client-win-", AC_PLATFORM_WINDOWS },
		{ "cisco-secure-client-win64-", AC_PLATFORM_WINDOWS },
		{ "cisco-secure-client-macos-", AC_PLATFORM_MACOS },
		{ "cisco-secure-client-linux64-", AC_PLATFORM_LINUX64 },
		{ "cisco-secure-client-linux-", AC_PLATFORM_LINUX },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		size_t len = strlen(prefixes[i].prefix);

		if (strncmp(name, prefixes[i].prefix, len) == 0) {
			switch (prefixes[i].platform) {
			case AC_PLATFORM_WINDOWS:
				*platform = &updates->windows;
				break;
			case AC_PLATFORM_WINDOWS_ARM64:
				*platform = &updates->windows_arm64;
				break;
			case AC_PLATFORM_MACOS:
				*platform = &updates->macos;
				break;
			case AC_PLATFORM_LINUX:
				*platform = &updates->linux;
				break;
			case AC_PLATFORM_LINUX64:
				*platform = &updates->linux64;
				break;
			}
			return name + len;
		}
	}

	return NULL;
}

static int ac_version_compare(const char *a, const char *b)
{
	const char *ap = a;
	const char *bp = b;

	while (*ap != 0 || *bp != 0) {
		unsigned long av = 0;
		unsigned long bv = 0;

		while (*ap != 0 && *ap != '.') {
			if (!isdigit((unsigned char)*ap))
				return strcmp(a, b);
			av = av * 10 + (unsigned long)(*ap - '0');
			ap++;
		}

		while (*bp != 0 && *bp != '.') {
			if (!isdigit((unsigned char)*bp))
				return strcmp(a, b);
			bv = bv * 10 + (unsigned long)(*bp - '0');
			bp++;
		}

		if (av > bv)
			return 1;
		if (av < bv)
			return -1;

		if (*ap == '.')
			ap++;
		if (*bp == '.')
			bp++;
	}

	return 0;
}

static const char *parse_package_filename(void *pool,
					  struct ac_update_st *updates,
					  const char *name,
					  struct ac_platform_st **platform)
{
	const char *version;
	const char *end;
	size_t version_len;
	char *version_copy;

	if (!valid_webdeploy_filename(name))
		return NULL;

	version = match_prefix(name, updates, platform);
	if (version == NULL)
		return NULL;

	end = strchr(version, '-');
	if (end == NULL)
		return NULL;

	version_len = (size_t)(end - version);
	if (version_len == 0)
		return NULL;

	for (size_t i = 0; i < version_len; i++) {
		if (!isdigit((unsigned char)version[i]) && version[i] != '.')
			return NULL;
	}

	version_copy = talloc_strndup(pool, version, version_len);
	if (version_copy == NULL)
		return NULL;

	if ((*platform)->version == NULL ||
	    ac_version_compare(version_copy, (*platform)->version) > 0) {
		(*platform)->version = version_copy;
		(*platform)->filename = talloc_strdup(pool, name);
		if ((*platform)->filename == NULL)
			return NULL;
	} else {
		talloc_free(version_copy);
	}

	return version;
}

static const struct ac_platform_st *
select_request_platform(worker_st *ws, struct ac_update_st *updates)
{
	const char *platform = ws->req.devplatform;
	const char *agent = ws->req.user_agent;

	if (strstr(platform, "Windows_ARM64") != NULL ||
	    strstr(agent, "Windows_ARM64") != NULL ||
	    strstr(agent, "win-arm64") != NULL)
		return &updates->windows_arm64;

	if (strstr(platform, "Windows") != NULL ||
	    strstr(agent, "Windows") != NULL || strstr(agent, "win") != NULL)
		return &updates->windows;

	if (strstr(platform, "Linux_64") != NULL ||
	    strstr(agent, "Linux_64") != NULL ||
	    strstr(agent, "linux64") != NULL)
		return &updates->linux64;

	if (strstr(platform, "Linux") != NULL ||
	    strstr(agent, "Linux") != NULL || strstr(agent, "linux") != NULL)
		return &updates->linux;

	if (strstr(platform, "Darwin") != NULL ||
	    strstr(agent, "Darwin") != NULL || strstr(agent, "macos") != NULL ||
	    strstr(agent, "macOS") != NULL)
		return &updates->macos;

	return NULL;
}

static void set_platform_names(struct ac_update_st *updates)
{
	updates->windows.name = "Windows";
	updates->windows_arm64.name = "Windows_ARM64";
	updates->macos.name = "Darwin_i386";
	updates->linux.name = "Linux";
	updates->linux64.name = "Linux_64";
}

static void load_anyconnect_updates(void *pool, struct ac_update_st *updates)
{
	DIR *dir;
	struct dirent *de;

	memset(updates, 0, sizeof(*updates));
	set_platform_names(updates);

	dir = opendir(AC_BINARIES_DIR);
	if (dir == NULL)
		return;

	while ((de = readdir(dir)) != NULL) {
		struct ac_platform_st *platform = NULL;

		if (de->d_name[0] == '.')
			continue;

		(void)parse_package_filename(pool, updates, de->d_name,
					     &platform);
	}

	closedir(dir);
}

static int append_manifest_file(worker_st *ws, char **xml,
				const struct ac_platform_st *platform)
{
	if (platform->filename == NULL)
		return 0;

	*xml = talloc_asprintf_append(
		*xml,
		"<file version=\"%s\" id=\"VPNCore\" is_core=\"yes\" "
		"type=\"%s\" action=\"install\">"
		"<uri>binaries/%s</uri>"
		"<display-name>AnyConnect Secure Mobility Client</display-name>"
		"</file>\n",
		platform->version, filename_ext(platform->filename),
		platform->filename);
	if (*xml == NULL)
		return -1;

	return 0;
}

static char *generate_anyconnect_manifest(worker_st *ws)
{
	struct ac_update_st updates;
	const struct ac_platform_st *platform;
	void *pool;
	char *xml;

	pool = talloc_new(ws);
	if (pool == NULL)
		return NULL;

	load_anyconnect_updates(pool, &updates);
	platform = select_request_platform(ws, &updates);

	xml = talloc_strdup(ws, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<vpn rev=\"1.0\">\n");
	if (xml == NULL)
		goto cleanup;

	if (platform != NULL && append_manifest_file(ws, &xml, platform) < 0)
		goto cleanup;

	xml = talloc_asprintf_append(xml, "</vpn>\n");
cleanup:
	talloc_free(pool);
	return xml;
}

static char *generate_anyconnect_version(worker_st *ws)
{
	struct ac_update_st updates;
	const struct ac_platform_st *platform;
	void *pool;
	char *txt;

	pool = talloc_new(ws);
	if (pool == NULL)
		return NULL;

	load_anyconnect_updates(pool, &updates);
	platform = select_request_platform(ws, &updates);

	if (platform == NULL || platform->version == NULL) {
		talloc_free(pool);
		return talloc_strdup(ws, VPN_VERSION);
	}

	txt = talloc_strdup(ws, platform->version);
	if (txt == NULL)
		goto cleanup;

	for (char *p = txt; *p != 0; p++) {
		if (*p == '.')
			*p = ',';
	}

	txt = talloc_asprintf_append(txt, "\n");
cleanup:
	talloc_free(pool);
	return txt;
}

int get_string_handler(worker_st *ws, unsigned int http_ver)
{
	char *data;

	oclog(ws, LOG_HTTP_DEBUG, "requested fixed string: %s", ws->req.url);
	if (!strcmp(ws->req.url, "/1/binaries/update.txt")) {
		if (ws->req.user_agent_type != AGENT_ANYCONNECT)
			return send_data(ws, http_ver, "text/plain",
					 VPN_VERSION, sizeof(VPN_VERSION) - 1);

		data = generate_anyconnect_version(ws);
		if (data == NULL)
			return -1;
		return send_data(ws, http_ver, "text/plain", data,
				 strlen(data));
	} else if (!strcmp(ws->req.url, "/1/VPNManifest.xml") ||
		   !strcmp(ws->req.url, "/VPNManifest.xml")) {
		if (ws->req.user_agent_type != AGENT_ANYCONNECT)
			return send_data(ws, http_ver, "text/xml", XML_START,
					 sizeof(XML_START) - 1);

		data = generate_anyconnect_manifest(ws);
		if (data == NULL)
			return -1;
		return send_data(ws, http_ver, "text/xml", data, strlen(data));
	} else {
		return send_data(ws, http_ver, "text/xml", XML_START,
				 sizeof(XML_START) - 1);
	}
}

#define SH_SCRIPT       \
	"#!/bin/sh\n\n" \
	"exit 0"

int get_dl_handler(worker_st *ws, unsigned int http_ver)
{
	oclog(ws, LOG_HTTP_DEBUG, "requested downloader: %s", ws->req.url);
	return send_data(ws, http_ver, "application/x-shellscript", SH_SCRIPT,
			 sizeof(SH_SCRIPT) - 1);
}

int get_anyconnect_binary_handler(worker_st *ws, unsigned int http_ver)
{
	struct ac_update_st updates;
	struct ac_platform_st *platform = NULL;
	const char *filename = ws->req.url + sizeof(AC_BINARIES_URL) - 1;
	char path[_POSIX_PATH_MAX];
	struct stat st;
	void *pool;
	int ret;

	pool = talloc_new(ws);
	if (pool == NULL)
		return -1;

	memset(&updates, 0, sizeof(updates));
	set_platform_names(&updates);

	if (filename[0] == 0 || strchr(filename, '/') != NULL ||
	    parse_package_filename(pool, &updates, filename, &platform) ==
		    NULL) {
		talloc_free(pool);
		response_404(ws, http_ver);
		return -1;
	}
	talloc_free(pool);

	ret = snprintf(path, sizeof(path), "%s/%s", AC_BINARIES_DIR, filename);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		response_404(ws, http_ver);
		return -1;
	}

	ret = stat(path, &st);
	if (ret == -1 || !S_ISREG(st.st_mode)) {
		response_404(ws, http_ver);
		return -1;
	}
	if (st.st_size < 0 || st.st_size > UINT_MAX) {
		response_404(ws, http_ver);
		return -1;
	}

	cstp_cork(ws);
	if (send_headers(ws, http_ver, "application/octet-stream",
			 (unsigned int)st.st_size) < 0 ||
	    cstp_uncork(ws) < 0)
		return -1;

	ret = cstp_send_file(ws, path);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s", path,
		      gnutls_strerror(ret));
		return -1;
	}

	return 0;
}

#define EMPTY_MSG "<html></html>\n"

int get_empty_handler(worker_st *ws, unsigned int http_ver)
{
	return send_data(ws, http_ver, "text/html", EMPTY_MSG,
			 sizeof(EMPTY_MSG) - 1);
}

#endif
