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

require("dumper");

function dump(...)
  print(DataDumper(...), "\n---")
  end

require("majordomo_lib");

function main()
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
		local sorted = get_sorted_items(addr, items, "u_count");
		io.stdout:write(string.format("%s\n", addr));
		for _, item in ipairs(sorted) do
			proto, _, dst, port = split_key(item.key);
			io.stdout:write(string.format("\t - %s - (%s/%s) - (%d/%d/%d) - (%d/%d/%d)\n",
				dst, port, proto,
				item.value.d_count, item.value.d_size, item.value.d_data_size,
				item.value.u_count, item.value.u_size, item.value.u_data_size)
			);
		end
	end

end

main();
