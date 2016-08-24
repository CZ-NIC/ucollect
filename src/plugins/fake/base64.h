/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2016 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_FAKE_BASE64_H
#define UCOLLECT_FAKE_BASE64_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Decode the buffer from base64 to normal data. The data are overwritten.
 * The input is NULL-terminated string and it returns the size of decoded
 * data. The output is NULL-terminated for convenience (however, the output
 * size does not include this NULL-terminator and the data may contain
 * other NULL-bytes).
 *
 * Note that the base64 decoded data are never larger than the encoded
 * equivalent, so it's OK to reuse that buffer.
 *
 * Any invalid characters are ignored.
 */
size_t base64_decode_inplace(uint8_t *buffer) __attribute__((nonnull));

#endif
