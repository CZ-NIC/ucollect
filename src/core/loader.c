#include "loader.h"
#include "util.h"
#include "plugin.h"

#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>

void *plugin_load(const char *libname, struct plugin *target) {
	ulog(LOG_INFO, "Loading plugin library %s\n", libname);
	dlerror(); // Reset errors
#ifdef PLUGIN_PATH
	char libpath[PATH_MAX + 1];
	snprintf(libpath, PATH_MAX + 1, PLUGIN_PATH "/%s", libname);
#else
	const char *libpath = libname;
#endif
	void *library = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
	if (!library) {
		ulog(LOG_ERROR, "Can't load plugin %s: %s\n", libpath, dlerror());
		return NULL;
	}
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
		ulog(LOG_ERROR, "The library %s doesn't contain plugin_info() - is it a plugin?: %s\n", libpath, error);
		dlclose(library);
		return NULL;
	}
	struct plugin *info = plugin_info();
	*target = *info;
	return library;
}

void plugin_unload(void *library) {
	ulog(LOG_INFO, "Unloading plugin library\n");
	dlclose(library);
}
