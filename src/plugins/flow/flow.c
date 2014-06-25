/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "flow.h"

#include <string.h>

bool flow_cmp(const struct flow *_1, const struct flow *_2) {
	if (_1->ipv != _2->ipv)
		return false;
	if (_1->proto != _2->proto)
		return false;
	for (size_t i = 0; i < 2; i ++) {
		if (_1->ports[i] != _2->ports[i])
			return false;
		if (memcmp(_1->addrs[i], _2->addrs[i], sizeof _2->addrs[i]) != 0)
			return false;
	}
	return true;
}

void flow_parse(struct flow *target, const struct packet_info *packet) {
	// TODO: Implement
	memset(target, 0, sizeof *target);
}

size_t flow_size(const struct flow *flow) {
	// TODO: Implement
	return 0;
}

void flow_render(uint8_t *dst, size_t dst_size, const struct flow *flow) {
	// TODO: Implement
}
