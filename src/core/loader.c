/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "loader.h"
#include "util.h"
#include "plugin.h"
#include "pluglib.h"
#include "tunable.h"

#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#ifdef STATIC

#include <string.h>
/*
 * The loader does not work with static linkage. We provide a stub here with
 * hard-coded plugins.
 */
struct plugin *plugin_info_count(void);
struct plugin *plugin_info_buckets(void);

static int dummy;

void *plugin_load(const char *libname, struct plugin *target) {
	ulog(LLOG_INFO, "Want plugin %s\n", libname);
	if (strcmp(libname, "libplugin_count.so") == 0) {
		*target = *plugin_info_count();
		return &dummy;
	} else if (strcmp(libname, "libplugin_buckets.so") == 0) {
		*target = *plugin_info_buckets();
		return &dummy;
	}
	ulog(LLOG_ERROR, "Dynamic loading not allowed\n");
	return NULL;
}

void plugin_unload(void *library) {
	(void) library;
}

#else

#include <dlfcn.h>

static void *lib_load(const char *libname, uint8_t *hash, char *libpath) {
	ulog(LLOG_INFO, "Loading plugin library %s\n", libname);
	dlerror(); // Reset errors
#ifdef PLUGIN_PATH
	snprintf(libpath, PATH_MAX + 1, PLUGIN_PATH "/%s", libname);
	int libfile = open(libpath, O_RDONLY);
	if (libfile == -1) {
		ulog(LLOG_ERROR, "Plugin %s doesn't exist: %s\n", libpath, strerror(errno));
		return NULL;
	}
	SHA256_CTX context;
	SHA256_Init(&context);
#define MAX_BUF 1024
	uint8_t buffer[MAX_BUF];
	ssize_t result;
	while ((result = read(libfile, buffer, MAX_BUF)) > 0)
		SHA256_Update(&context, buffer, result);
	if (result < 0) {
		ulog(LLOG_ERROR, "Error reading from plugin library %s: %s\n", libpath, strerror(errno));
		close(libfile);
		return NULL;
	}
	close(libfile);
	uint8_t output[SHA256_DIGEST_LENGTH];
	SHA256_Final(output, &context);
	memcpy(hash, output, CHALLENGE_LEN / 2);
#else
	const char *libpath = libname;
	ulog(LLOG_WARN, "Not having complete path. Can't compute hash, there might be problems logging in\n");
	memset(hash, 0, CHALLENGE_LEN / 2);
#endif
	void *library = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
	if (!library) {
		ulog(LLOG_ERROR, "Can't load plugin %s: %s\n", libpath, dlerror());
		return NULL;
	}
	return library;
}

void *plugin_load(const char *libname, struct plugin *target, uint8_t *hash) {
	char libpath[PATH_MAX + 1];
	void *library = lib_load(libname, hash, libpath);
	if (!library)
		return NULL;
	struct plugin *(*plugin_info)();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-pedantic"
	/*
	 * This is wrong, we can't cast between pointer to function and pointer to
	 * object. But there seems to be no way without it.
	 */
	*(void **)(&plugin_info) = dlsym(library, "plugin_info");
#pragma GCC diagnostic pop
	const char *error = dlerror();
	if (error) {
		ulog(LLOG_ERROR, "The library %s doesn't contain plugin_info() - is it a plugin?: %s\n", libpath, error);
		dlclose(library);
		return NULL;
	}
	struct plugin *info = plugin_info();
	*target = *info;
	return library;
}

void *pluglib_load(const char *libname, struct pluglib *target, uint8_t *hash) {
	char libpath[PATH_MAX + 1];
	void *library = lib_load(libname, hash, libpath);
	if (!library)
		return NULL;
	struct pluglib *(*pluglib_info)();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-pedantic"
	/*
	 * This is wrong, we can't cast between pointer to function and pointer to
	 * object. But there seems to be no way without it.
	 */
	*(void **)(&pluglib_info) = dlsym(library, "pluglib_info");
#pragma GCC diagnostic pop
	const char *error = dlerror();
	if (error) {
		ulog(LLOG_ERROR, "The library %s doesn't contain pluglib_info() - is it a plugin library?: %s\n", libpath, error);
		dlclose(library);
		return NULL;
	}
	struct pluglib *info = pluglib_info();
	*target = *info;
	return library;
}

void plugin_unload(void *library) {
	ulog(LLOG_INFO, "Unloading plugin library\n");
	dlclose(library);
}
#endif
