#include <Python.h>
#include <dlfcn.h>
#include <atsha204.h>

/*
 * As linking to other libraries from python extensions is tricky,
 * we do fully dynamic loading of the library with dlopen.
 *
 * Also, most of the error checking is done by assert instead of
 * python exceptions, out of laziness.
 */

static PyObject *atsha_do_hmac(PyObject *self, PyObject *args) {
	(void) self;
	int size_serial, size_key, size_challenge;
	unsigned char slot_id;
	const uint8_t *serial, *key, *challenge;
	if (!PyArg_ParseTuple(args, "bs#s#s#", &slot_id, &serial, &size_serial, &key, &size_key, &challenge, &size_challenge))
		return NULL;
	assert(size_key == 32);
	assert(size_challenge == 32);
	struct atsha_handle *crypto = atsha_open_server_emulation(slot_id, serial, key);
	atsha_big_int challenge_s, response_s;
	challenge_s.bytes = 32;
	memcpy(challenge_s.data, challenge, 32);
	int result = atsha_challenge_response(crypto, challenge_s, &response_s);
	assert(result == ATSHA_ERR_OK);
	atsha_close(crypto);
	return Py_BuildValue("s#", response_s.data, (int) response_s.bytes);
}

static PyMethodDef atsha_methods[] = {
	{"hmac", atsha_do_hmac, METH_VARARGS, NULL},
	{NULL}
};

PyMODINIT_FUNC initatsha204(void) {
	Py_InitModule("atsha204", atsha_methods);
}
