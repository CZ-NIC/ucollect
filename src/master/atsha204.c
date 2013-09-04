/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013 CZ.NIC

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
