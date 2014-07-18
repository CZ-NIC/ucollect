#!/usr/bin/env lua

--[[
Copyright 2014, CZ.NIC z.s.p.o. (http://www.nic.cz/)

This file is part of NUCI configuration server.

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

local MAX_ITEMS_PER_CLIENT = 6000

 --This names have to be synced with Majordomo plugin
local KW_OTHER_PROTO = "both"
local KW_OTHER_DSTIP = "all"
local KW_OTHER_PORT = "all"

function eliminate_items(addr, items, count)
	-- Compute key string only once
	local others_key = table.concat({ KW_OTHER_PROTO, addr, KW_OTHER_DSTIP, KW_OTHER_PORT }, ",");

	-- Prepare table for recomputed items
	local new_items = {};
	if items[others_key] then
		new_items[others_key] = items[others_key];
	else
		new_items[others_key] = { count = 0, size = 0, data_size = 0 };
	end

	-- Prepare array set to sorting
	sorted_array = {};
	for k, v in pairs(items) do
		table.insert(sorted_array, {key = k, value = v});
	end

	table.sort(sorted_array, function(x, y) return x.value.count > y.value.count  end)

	-- Eliminate items
	for i, _ in ipairs(sorted_array) do
		if i > MAX_ITEMS_PER_CLIENT and sorted_array[i].key ~= others_key then
			new_items[others_key].count = new_items[others_key].count + sorted_array[i].value.count;
			new_items[others_key].size = new_items[others_key].size + sorted_array[i].value.size;
			new_items[others_key].data_size = new_items[others_key].data_size + sorted_array[i].value.data_size;
		else
			new_items[sorted_array[i].key] = sorted_array[i].value;
		end
	end

	return new_items;
end

function read_file(db, file)
	local f = io.open(file, "r");
	if not f then
		io.stderr:write(string.format("Cannot open file %s\n", file));
		os.exit(1);
	end

	for line in f:lines() do
		--Use port as string... we need value "all"
		proto, src, dst, port, count, size, data_size = line:match("(%w+),([%w\.:]+),([%w\.:]+),(%w+),(%d+),(%d+),(%d+)");
		key = table.concat({ proto, src, dst, port }, ",");
		if (key ~= "") then
			if not db[src] then
				db[src] = { };
			end
			if not db[src][key] then
				db[src][key] = { count = tonumber(count), size = tonumber(size), data_size = tonumber(data_size) }
			else
				db[src][key].count = db[src][key].count + tonumber(count);
				db[src][key].size = db[src][key].size + tonumber(size);
				db[src][key].data_size = db[src][key].data_size + tonumber(data_size);
			end
		end
	end

	f:close();
end

function main()
	if #arg ~= 3 then
		io.stderr:write(string.format("Usage: %s file1 file2 merge_to\n", arg[0]));
		os.exit(1);
	end

	db = {}

	read_file(db, arg[1]);
	read_file(db, arg[2]);

	for addr, items in pairs(db) do
		local count = 0;
		-- Count items... really the only way?
		for _, _ in pairs(items) do
			count = count + 1;
		end
		if count > MAX_ITEMS_PER_CLIENT then
			db[addr] = eliminate_items(addr, items, count);
		end
	end

	local ofile = io.open(arg[3], "w");
	if not ofile then
		io.stderr:write(string.format("Cannot open file %s for writing\n", arg[3]));
		os.exit(1);
	end
	for _, record in pairs(db) do
		for key, value in pairs(record) do
			ofile:write(string.format("%s,%d,%d,%d\n", key, value.count, value.size, value.data_size));
		end
	end
	ofile:close();

end

main();
