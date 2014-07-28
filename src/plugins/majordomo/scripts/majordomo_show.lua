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

 --This names have to be synced with Majordomo plugin
local KW_OTHER_PROTO = "both"
local KW_OTHER_DSTIP = "all"
local KW_OTHER_PORT = "all"

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
	if #arg ~= 1 then
		io.stderr:write(string.format("Usage: %s file_to_dump\n", arg[0]));
		os.exit(1);
	end

	db = {}
	read_file(db, arg[1]);

	for addr, items in pairs(db) do
		io.stdout:write(string.format("%s\n", addr));
		for key, value in pairs(items) do
			-- Disjoin key again
			proto, _, dst, port = key:match("(%w+),([%w\.:]+),([%w\.:]+),(%w+)");
			io.stdout:write(string.format("\t - %s - (%s/%s) - (%d/%d/%d)\n", dst, port, proto, value.count, value.size, value.data_size));
		end
	end

end

main();
