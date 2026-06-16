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

static int send_file_if_exists(worker_st *ws, unsigned int http_ver,
			       const char *content_type, const char *path)
{
	struct stat st;
	int ret;

	ret = stat(path, &st);
	if (ret == -1 || !S_ISREG(st.st_mode))
		return 0;
	if (st.st_size < 0 || st.st_size > UINT_MAX)
		return -1;

	cstp_cork(ws);
	if (send_headers(ws, http_ver, content_type, (unsigned int)st.st_size) <
		    0 ||
	    cstp_uncork(ws) < 0)
		return -1;

	ret = cstp_send_file(ws, path);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s", path,
		      gnutls_strerror(ret));
		return -1;
	}

	return 1;
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
#define AC_WEBDEPLOY_DIR "1/webdeploy"

struct ac_platform_st {
	const char *name;
	const char *version;
	const char *filename;
	const char *webdeploy_dir;
};

struct ac_update_st {
	struct ac_platform_st windows;
	struct ac_platform_st windows_arm64;
	struct ac_platform_st macos;
	struct ac_platform_st linux;
	struct ac_platform_st linux64;
	struct ac_platform_st linux_arm64;
};

static void load_anyconnect_updates(void *pool, struct ac_update_st *updates);

static bool valid_anyconnect_filename(const char *name)
{
	const char *p;

	if (name == NULL || name[0] == 0)
		return false;

	for (p = name; *p != 0; p++) {
		if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' ||
		      *p == '-'))
			return false;
	}

	return true;
}

static bool valid_webdeploy_filename(const char *name)
{
	if (!valid_anyconnect_filename(name))
		return false;

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
		AC_PLATFORM_LINUX_ARM64,
	};
	static const struct {
		const char *prefix;
		enum ac_platform_id platform;
	} prefixes[] = {
		{ "anyconnect-win-arm64-", AC_PLATFORM_WINDOWS_ARM64 },
		{ "anyconnect-win-", AC_PLATFORM_WINDOWS },
		{ "anyconnect-win64-", AC_PLATFORM_WINDOWS },
		{ "anyconnect-macos-", AC_PLATFORM_MACOS },
		{ "anyconnect-linux-arm64-", AC_PLATFORM_LINUX_ARM64 },
		{ "anyconnect-linux64-", AC_PLATFORM_LINUX64 },
		{ "anyconnect-linux-", AC_PLATFORM_LINUX },
		{ "cisco-secure-client-win-arm64-", AC_PLATFORM_WINDOWS_ARM64 },
		{ "cisco-secure-client-win-", AC_PLATFORM_WINDOWS },
		{ "cisco-secure-client-win64-", AC_PLATFORM_WINDOWS },
		{ "cisco-secure-client-macos-", AC_PLATFORM_MACOS },
		{ "cisco-secure-client-linux-arm64-", AC_PLATFORM_LINUX_ARM64 },
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
			case AC_PLATFORM_LINUX_ARM64:
				*platform = &updates->linux_arm64;
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

static char *client_version_from_agent(void *pool, const char *agent)
{
	const char *p = agent;

	while (*p != 0) {
		const char *start;
		size_t len;
		unsigned int dots = 0;

		while (*p != 0 && !isdigit((unsigned char)*p))
			p++;
		start = p;

		while (*p != 0 && (isdigit((unsigned char)*p) || *p == '.')) {
			if (*p == '.')
				dots++;
			p++;
		}

		len = (size_t)(p - start);
		if (dots >= 2 && len > dots)
			return talloc_strndup(pool, start, len);
	}

	return NULL;
}

static char *version_to_update_txt(void *pool, const char *version)
{
	char *txt;

	txt = talloc_strdup(pool, version);
	if (txt == NULL)
		return NULL;

	for (char *p = txt; *p != 0; p++) {
		if (*p == '.')
			*p = ',';
	}

	return talloc_asprintf_append(txt, "\n");
}

static bool webdeploy_metadata_exists(const char *dir)
{
	char path[_POSIX_PATH_MAX];
	struct stat st;
	int ret;

	if (dir == NULL)
		return false;

	ret = snprintf(path, sizeof(path), "%s/VPNManifest.xml", dir);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return false;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
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
	char *webdeploy_dir;
	int cmp;
	bool candidate_has_metadata;
	bool current_has_metadata;

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

	webdeploy_dir = talloc_asprintf(pool, "%s/%s", AC_WEBDEPLOY_DIR, name);
	if (webdeploy_dir == NULL)
		return NULL;

	candidate_has_metadata = webdeploy_metadata_exists(webdeploy_dir);
	current_has_metadata =
		webdeploy_metadata_exists((*platform)->webdeploy_dir);

	cmp = (*platform)->version == NULL ?
		      1 :
		      ac_version_compare(version_copy, (*platform)->version);

	if ((*platform)->version == NULL ||
	    (candidate_has_metadata && !current_has_metadata) ||
	    (candidate_has_metadata == current_has_metadata && cmp > 0)) {
		(*platform)->version = version_copy;
		(*platform)->filename = talloc_strdup(pool, name);
		if ((*platform)->filename == NULL)
			return NULL;
		(*platform)->webdeploy_dir = webdeploy_dir;
	} else {
		talloc_free(version_copy);
		talloc_free(webdeploy_dir);
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
	    strstr(agent, "Windows") != NULL)
		return &updates->windows;

	if (strstr(platform, "Linux_64") != NULL ||
	    strstr(agent, "Linux_64") != NULL ||
	    strstr(agent, "linux64") != NULL)
		return &updates->linux64;

	if (strstr(platform, "Linux_ARM64") != NULL ||
	    strstr(platform, "Linux_arm64") != NULL ||
	    strstr(agent, "Linux_ARM64") != NULL ||
	    strstr(agent, "linux-arm64") != NULL)
		return &updates->linux_arm64;

	if (strstr(platform, "Linux") != NULL ||
	    strstr(agent, "Linux") != NULL || strstr(agent, "linux") != NULL)
		return &updates->linux;

	if (strstr(platform, "Darwin") != NULL ||
	    strstr(agent, "Darwin") != NULL || strstr(agent, "macos") != NULL ||
	    strstr(agent, "macOS") != NULL)
		return &updates->macos;

	return NULL;
}

static bool client_needs_update(worker_st *ws, void *pool,
				const struct ac_platform_st *platform)
{
	char *client_version;

	if (platform == NULL || platform->version == NULL)
		return false;

	client_version = client_version_from_agent(pool, ws->req.user_agent);
	return client_version == NULL ||
	       ac_version_compare(platform->version, client_version) > 0;
}

static bool request_is_downloader(worker_st *ws)
{
	return strstr(ws->req.user_agent, "Downloader") != NULL;
}

static const struct ac_platform_st *
request_update_platform(worker_st *ws, void *pool, struct ac_update_st *updates)
{
	const struct ac_platform_st *platform;

	load_anyconnect_updates(pool, updates);
	platform = select_request_platform(ws, updates);
	if (platform == NULL || platform->version == NULL)
		return NULL;

	if (request_is_downloader(ws) ||
	    client_needs_update(ws, pool, platform))
		return platform;

	return NULL;
}

static int webdeploy_path(char *path, size_t path_size,
			  const struct ac_platform_st *platform,
			  const char *name)
{
	int ret;

	if (platform == NULL || platform->webdeploy_dir == NULL)
		return -1;

	ret = snprintf(path, path_size, "%s/%s", platform->webdeploy_dir, name);
	if (ret < 0 || (size_t)ret >= path_size)
		return -1;

	return 0;
}

static int send_platform_webdeploy_file(worker_st *ws, unsigned int http_ver,
					const char *content_type,
					const char *name)
{
	struct ac_update_st updates;
	const struct ac_platform_st *platform;
	char path[_POSIX_PATH_MAX];
	void *pool;
	int ret;

	pool = talloc_new(ws);
	if (pool == NULL)
		return -1;

	platform = request_update_platform(ws, pool, &updates);
	if (webdeploy_path(path, sizeof(path), platform, name) < 0) {
		talloc_free(pool);
		return 0;
	}

	ret = send_file_if_exists(ws, http_ver, content_type, path);
	talloc_free(pool);
	return ret;
}

static void set_platform_names(struct ac_update_st *updates)
{
	updates->windows.name = "Windows";
	updates->windows_arm64.name = "Windows_ARM64";
	updates->macos.name = "Darwin_i386";
	updates->linux.name = "Linux";
	updates->linux64.name = "Linux_64";
	updates->linux_arm64.name = "Linux_ARM64";
}

static void load_anyconnect_updates(void *pool, struct ac_update_st *updates)
{
	DIR *dir;
	struct dirent *de;

	memset(updates, 0, sizeof(*updates));
	set_platform_names(updates);

	/* Prefer prepared webdeploy directories over legacy package files. */
	dir = opendir(AC_WEBDEPLOY_DIR);
	if (dir != NULL) {
		while ((de = readdir(dir)) != NULL) {
			struct ac_platform_st *platform = NULL;

			if (de->d_name[0] == '.')
				continue;

			(void)parse_package_filename(pool, updates, de->d_name,
						     &platform);
		}

		closedir(dir);
	}

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

static int send_selected_webdeploy_binary(worker_st *ws, unsigned int http_ver,
					  const char *filename)
{
	char path[_POSIX_PATH_MAX];
	int ret;

	/* Cisco manifests use /1/binaries URLs even for prepared webdeploy sets. */
	ret = snprintf(path, sizeof(path), "binaries/%s", filename);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	return send_platform_webdeploy_file(ws, http_ver,
					    "application/octet-stream", path);
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

	if (platform != NULL && platform->version != NULL) {
		char *client_version =
			client_version_from_agent(pool, ws->req.user_agent);

		if ((client_version == NULL ||
		     ac_version_compare(platform->version, client_version) >
			     0) &&
		    append_manifest_file(ws, &xml, platform) < 0)
			goto cleanup;
	}

	if (platform != NULL && platform->version == NULL &&
	    append_manifest_file(ws, &xml, platform) < 0)
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
	char *client_version;
	void *pool;
	char *txt;

	pool = talloc_new(ws);
	if (pool == NULL)
		return NULL;

	load_anyconnect_updates(pool, &updates);
	platform = select_request_platform(ws, &updates);
	client_version = client_version_from_agent(pool, ws->req.user_agent);

	if (platform != NULL && platform->version != NULL &&
	    (client_version == NULL ||
	     ac_version_compare(platform->version, client_version) > 0)) {
		txt = version_to_update_txt(ws, platform->version);
		goto cleanup;
	}

	if (client_version != NULL) {
		txt = version_to_update_txt(ws, client_version);
		goto cleanup;
	}

	if (platform == NULL || platform->version == NULL) {
		talloc_free(pool);
		return talloc_strdup(ws, VPN_VERSION);
	}

	txt = talloc_strdup(ws, VPN_VERSION);
cleanup:
	talloc_free(pool);
	return txt;
}

int get_string_handler(worker_st *ws, unsigned int http_ver)
{
	char *data;

	oclog(ws, LOG_HTTP_DEBUG, "requested fixed string: %s", ws->req.url);
	if (!strcmp(ws->req.url, "/1/binaries/update.txt")) {
		cookie_authenticate_or_exit(ws);

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
		int ret;

		cookie_authenticate_or_exit(ws);

		if (ws->req.user_agent_type != AGENT_ANYCONNECT)
			return send_data(ws, http_ver, "text/xml", XML_START,
					 sizeof(XML_START) - 1);

		ret = send_platform_webdeploy_file(ws, http_ver, "text/xml",
						   "VPNManifest.xml");
		if (ret != 0)
			return ret < 0 ? -1 : 0;

		data = generate_anyconnect_manifest(ws);
		if (data == NULL)
			return -1;
		return send_data(ws, http_ver, "text/xml", data, strlen(data));
	} else if (!strcmp(ws->req.url, "/1/VPNHashManifest.xml") ||
		   !strcmp(ws->req.url, "/VPNHashManifest.xml")) {
		int ret;

		cookie_authenticate_or_exit(ws);

		ret = send_platform_webdeploy_file(ws, http_ver, "text/xml",
						   "VPNHashManifest.xml");
		if (ret != 0)
			return ret < 0 ? -1 : 0;

		response_404(ws, http_ver);
		return -1;
	} else {
		return send_data(ws, http_ver, "text/xml", XML_START,
				 sizeof(XML_START) - 1);
	}
}

static int send_platform_downloader(worker_st *ws, unsigned int http_ver,
				    const char *name)
{
	char path[_POSIX_PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "binaries/%s", name);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	return send_platform_webdeploy_file(ws, http_ver,
					    "application/octet-stream", path);
}

int get_dl_handler(worker_st *ws, unsigned int http_ver)
{
	int ret;

	oclog(ws, LOG_HTTP_DEBUG, "requested downloader: %s", ws->req.url);

	cookie_authenticate_or_exit(ws);

	ret = send_platform_downloader(ws, http_ver, "vpndownloader.sh");
	if (ret != 0)
		return ret < 0 ? -1 : 0;

	ret = send_platform_downloader(ws, http_ver, "vpndownloader.exe");
	if (ret != 0)
		return ret < 0 ? -1 : 0;

	return send_data(ws, http_ver, "application/x-shellscript",
			 "#!/bin/sh\n\nexit 0\n", 18);
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

	cookie_authenticate_or_exit(ws);

	pool = talloc_new(ws);
	if (pool == NULL)
		return -1;

	memset(&updates, 0, sizeof(updates));
	set_platform_names(&updates);

	if (!valid_anyconnect_filename(filename) ||
	    strchr(filename, '/') != NULL) {
		talloc_free(pool);
		response_404(ws, http_ver);
		return -1;
	}

	ret = send_selected_webdeploy_binary(ws, http_ver, filename);
	if (ret != 0) {
		talloc_free(pool);
		return ret < 0 ? -1 : 0;
	}

	if (!valid_webdeploy_filename(filename) ||
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

int get_platform_handler(worker_st *ws, unsigned int http_ver)
{
	return send_data(ws, http_ver, "text/html", "", 0);
}

#endif
