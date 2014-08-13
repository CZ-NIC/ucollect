#!/usr/bin/env lua

--[[
Copyright 2014, CZ.NIC z.s.p.o. (http://www.nic.cz/)

This script is part of majordomo plugin for ucollect

NUCI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NUCI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NUCI.  If not, see <http://www.gnu.org/licenses/>.
]]

package.path = package.path .. ';/usr/share/lcollect/lua/?.lua'
require("majordomo_lib");

function main()
	local _, MAKE_LOOKUP = majordomo_get_configuration();
	if MAKE_LOOKUP then
		ptrdb = get_inst_ptrdb();
		macdb = get_inst_macdb();
		ptrdb:deserialize();
		macdb:deserialize();
	end
	if #arg ~= 1 then
		io.stderr:write(string.format("Usage: %s file_to_dump\n", arg[0]));
		os.exit(1);
	end

	db = {}
	if not read_file(db, arg[1]) then
		io.stderr:write(string.format("Cannot open file %s\n", arg[1]));
		os.exit(2);
	end

	for addr, items in pairs(db) do
		local sorted = get_sorted_items(items, "u_count");
		if MAKE_LOOKUP and macdb:lookup(addr) then
			io.stdout:write(string.format("%s (%s)\n", addr, macdb:lookup(addr)));
		else
			io.stdout:write(string.format("%s\n", addr));
		end
		for _, item in ipairs(sorted) do
			local proto, _, dst, port = split_key(item.key);
				if ptrdb then
					dst = ptrdb:lookup(dst) or dst;
				end
			io.stdout:write(string.format("\t - %s - (%s/%s) - (%f/%f/%f) - (%f/%f/%f)\n",
				dst, port, proto,
				item.value.d_count, item.value.d_size, item.value.d_data_size,
				item.value.u_count, item.value.u_size, item.value.u_data_size)
			);
		end
	end

	if MAKE_LOOKUP then
		ptrdb:serialize();
		macdb:serialize();
	end

end

main();
