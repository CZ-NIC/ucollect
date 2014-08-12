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

require("os");

package.path = package.path .. ';/usr/share/lcollect/lua/?.lua'
require("majordomo_lib");

local CMD_INVALIDATE = "invalidate";
local CMD_PRECACHE = "precache";

function invalidate(db_path)
	os.execute("rm '" .. db_path .. "/majordomo_serialized_'*");
end

function precache(db_path)
	local ptrdb = get_inst_ptrdb();
	local macdb = get_inst_macdb();
	ptrdb:deserialize();
	macdb:deserialize();

	local handles = { };
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  DAILY_PREFIX .."'*", "r"));
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  HOURLY_PREFIX .."'*", "r"));
	table.insert(handles, io.popen("/bin/ls '" .. db_path .. "/" ..  MONTHLY_PREFIX .."'*", "r"));

	for _, handle in ipairs(handles) do
		for file in handle:lines() do
			local db = { };
			read_file(db, file);
			for addr, items in pairs(db) do
				macdb:lookup(addr);
				for key, _ in pairs(items) do
					local _, _, dst, _ = split_key(key);
					ptrdb:lookup(dst);
				end
			end
		end
		handle:close();
	end

	ptrdb:serialize();
	macdb:serialize();
end

function main()
	local DB_PATH, MAKE_LOOKUP = majordomo_get_configuration();

	if #arg ~= 1 then
		io.stderr:write(string.format("Usage: %s (%s|%s)\n", arg[0], CMD_PRECACHE, CMD_INVALIDATE));
		os.exit(1);
	end

	if arg[1] == CMD_INVALIDATE then
		invalidate(DB_PATH);

	elseif arg[1] == CMD_PRECACHE then
		if MAKE_LOOKUP then
			precache(DB_PATH);
		else
			io.stderr:write("Precache: Lookup is disabled");
			os.exdit(0);
		end
	end
end

main();
