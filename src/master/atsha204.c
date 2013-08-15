#include <Python.h>
#include <dlfcn.h>
#include <atsha204.h>

/*
 * As linking to other libraries from python extensions is tricky,
 * we do fully dynamic loading of the library with dlopen.
 */

static void *library;

static PyObject *atsha_do_hmac(PyObject *self, PyObject *args) {
	
}

struct atsha_handle *(*atsha_open_server_emulation_local)(const uint8_t *serial, const uint8_t *key);
void (*atsha_close_local)(struct atsha_handle *handle);
int (*atsha_challenge_response_local)(struct atsha_handle *handle, atsha_big_int challenge, atsha_big_int *response);

static PyMethodDef atsha_methods[] = {
	{"hmac", atsha_do_hmac, METH_VARARGS, NULL},
	{NULL}
};

static void *get_sym(const char *name) {
	void *sym = dlsym(library, name);
	assert(sym);
	return sym;
}

PyMODINIT_FUNC initatsha204(void) {
	library = dlopen("libatsha204.so", RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
	assert(library);
	// Assignment from void * to function pointer is illegal, but needed by the dynamic loading.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-pedantic"
	atsha_open_server_emulation_local = get_sym("atsha_open_server_emulation");
	atsha_close_local = get_sym("atsha_close");
	atsha_challenge_response_local = get_sym("atsha_challenge_response");
#pragma GCC diagnostic pop
	Py_InitModule("atsha204", atsha_methods);
}
