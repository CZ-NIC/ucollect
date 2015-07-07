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

function eliminate_items(addr, items, count, max_items_per_client)
	-- Compute key string only once
	local others_key = table.concat({ KW_OTHER_PROTO, addr, KW_OTHER_DSTIP, KW_OTHER_PORT }, ",");

	-- Prepare table for recomputed items
	local new_items = {};
	if items[others_key] then
		new_items[others_key] = items[others_key];
	else
		new_items[others_key] = { d_count = 0, d_size = 0, d_data_size = 0, u_count = 0, u_size = 0, u_data_size = 0 };
	end

	-- Prepare array set to sorting
	sorted_array = get_sorted_items(items, "u_count");

	-- Eliminate items
	for i, _ in ipairs(sorted_array) do
		if i > max_items_per_client and sorted_array[i].key ~= others_key then
			new_items[others_key].d_count = new_items[others_key].d_count + sorted_array[i].value.d_count;
			new_items[others_key].d_size = new_items[others_key].d_size + sorted_array[i].value.d_size;
			new_items[others_key].d_data_size = new_items[others_key].d_data_size + sorted_array[i].value.d_data_size;
			new_items[others_key].u_count = new_items[others_key].u_count + sorted_array[i].value.u_count;
			new_items[others_key].u_size = new_items[others_key].u_size + sorted_array[i].value.u_size;
			new_items[others_key].u_data_size = new_items[others_key].u_data_size + sorted_array[i].value.u_data_size;
		else
			new_items[sorted_array[i].key] = sorted_array[i].value;
		end
	end

	return new_items;
end

function main()
	if #arg ~= 3 then
		io.stderr:write(string.format("Usage: %s file1 file2 merge_to\n", arg[0]));
		os.exit(1);
	end

	local _, _, _, max_items_per_client = majordomo_get_configuration();

	db = {}

	if not read_file(db, arg[1]) then
		io.stderr:write(string.format("Cannot open file %s\n", arg[1]));
		os.exit(2);
	end
	if not read_file(db, arg[2]) then
		io.stderr:write(string.format("Cannot open file %s\n", arg[2]));
		os.exit(2);
	end

	for addr, items in pairs(db) do
		local count = 0;
		-- Count items... really the only way?
		for _, _ in pairs(items) do
			count = count + 1;
		end
		if count > max_items_per_client then
			db[addr] = eliminate_items(addr, items, count, max_items_per_client);
		end
	end

	local ofile = io.open(arg[3], "w");
	if not ofile then
		io.stderr:write(string.format("Cannot open file %s for writing\n", arg[3]));
		os.exit(2);
	end
	for _, record in pairs(db) do
		for key, value in pairs(record) do
			if value.resolved_name then
				ofile:write(string.format("%s,%f,%f,%f,%f,%f,%f,%s\n", key, value.d_count, value.d_size, value.d_data_size, value.u_count, value.u_size, value.u_data_size, value.resolved_name));
			else
				ofile:write(string.format("%s,%f,%f,%f,%f,%f,%f\n", key, value.d_count, value.d_size, value.d_data_size, value.u_count, value.u_size, value.u_data_size));
			end
		end
	end
	ofile:close();

end

main();
